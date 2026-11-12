#!/usr/bin/env python3
"""
DFIR enhancement: parallel single-file ingest.

The legacy path parses + builds + writes one file on a single core.  Profiling
showed that core saturated at ~32 k accounts/s (parse + 2x SHA1 _id + per-row
stat tally + insert_many), while MongoDB itself can absorb several hundred k
inserts/s.  So one file was leaving 31 of 32 cores idle.

This module splits a plain-text dump into N newline-aligned byte ranges and runs
one worker per range.  Each worker independently parses its slice, builds account
documents, tallies its own partial per-source histograms, and streams its own
insert_many() batches to Mongo over its own connection — so we get N concurrent
CPU parsers AND N concurrent write streams.  The parent merges the partial
histograms afterwards, so the stored per-source statistics are identical to the
single-threaded path (heavy hitters exact; only the rarely-seen long tail, which
was already approximate under the RAM cap, is merged from per-worker top-K).

Only self-contained line formats are split this way (see
SmartParse.PARALLEL_SAFE_FORMATS).  Multi-line 'blocks', compressed files and
tiny files fall back to the single-threaded path, which still works unchanged.
"""

import os
import queue
import logging
import threading
import pymongo
from time import sleep, monotonic
from multiprocessing import Process, Queue, Value

from .parser.file import File
from .parser.smartparse import SmartParse
from .source import Source
from .config import config

log = logging.getLogger('credshed.ingest_parallel')


# how many top entries each worker ships back for the pruned (long-tail) counters.
# A key only needs to survive in ONE worker's top-K to be merged exactly; a key
# frequent enough to land in the stored top-1000 is frequent in every ~1/N shard,
# so the stored histograms stay exact.  TLD counters are naturally bounded, so
# they come back whole.
_RETURN_TOPK_HOST = 60000     # domains / services
_RETURN_TOPK_WORD = 30000     # password / misc base words
_RETURN_TOPK_TLD = 60000      # email/service zones (naturally small, but dirty hosts can inflate)

# how long a worker keeps retrying an unreachable Mongo before giving up the
# batch and flagging the import partial, instead of hanging forever.
_WRITE_RETRY_SECONDS = 180


def _topk(counter, k):
    if len(counter) <= k:
        return dict(counter)
    return dict(sorted(counter.items(), key=lambda kv: kv[1], reverse=True)[:k])


def _flush_once(coll, docs, source_id):
    '''
    One insert_many(unordered) + duplicate-key provenance merge (an _id collision
    means the account already exists — add this source to its `s` array).  Raises
    PyMongoError on a transient failure so the caller can bound its retries.
    '''
    if not docs:
        return
    try:
        coll.insert_many(docs, ordered=False)
    except pymongo.errors.BulkWriteError as bwe:
        dup_ids, other = [], 0
        for e in bwe.details.get('writeErrors', []):
            if e.get('code') == 11000:
                _id = (e.get('op') or {}).get('_id')
                if _id is not None:
                    dup_ids.append(_id)
            else:
                other += 1
        if other:
            log.warning(f'{other} non-duplicate write error(s) for source {source_id}')
        if dup_ids:
            coll.bulk_write(
                [pymongo.UpdateOne({'_id': _id}, {'$addToSet': {'s': source_id}})
                 for _id in dup_ids], ordered=False)


def _writer_thread(coll, source_id, work_q, fail):
    '''
    Drains batches from an in-process queue and writes them to Mongo, overlapping
    the round-trip with parsing.  Retries a transient Mongo error but only until a
    deadline that PERSISTS across batches (so a sustained outage gives up ~once,
    not per-batch) — then it sets the shared `fail` flag and drops the batch so the
    worker reports the import as partial rather than the parent hanging forever.
    A None sentinel ends the thread; it keeps draining so the parser's put() never
    blocks permanently.
    '''
    deadline = None
    while True:
        batch = work_q.get()
        if batch is None:
            return
        while True:
            try:
                _flush_once(coll, batch, source_id)
                deadline = None
                break
            except pymongo.errors.PyMongoError as e:
                if deadline is None:
                    deadline = monotonic() + _WRITE_RETRY_SECONDS
                if monotonic() >= deadline:
                    fail[0] = True
                    log.error(f'writer gave up a {len(batch)}-doc batch after '
                              f'{_WRITE_RETRY_SECONDS}s of Mongo errors: {e}')
                    break
                sleep(5)
            except Exception as e:                   # poison doc etc. — drop + flag loudly
                fail[0] = True
                log.error(f'writer dropped a {len(batch)}-doc batch: {e}')
                break


def _put_live(work_q, item, writers):
    '''put() with backpressure, but never block forever if every writer has died'''
    while True:
        try:
            work_q.put(item, timeout=5)
            return
        except queue.Full:
            if not any(w.is_alive() for w in writers):
                raise RuntimeError('all writer threads died')


def _pool_worker(idx, path, encoding, presniff, source_id, batch_size,
                 task_q, result_q, done_bytes, write_threads, queue_depth):
    '''
    One persistent worker process.  Pulls (start, end) ranges from a shared task
    queue until a sentinel, parsing + building + tallying each (this thread) while
    its own writer thread(s) stream batches to Mongo concurrently.  Keeps ONE
    Mongo connection and ONE stats accumulator across all the ranges it handles,
    so splitting the file into many small ranges (work-stealing) balances uneven
    account density WITHOUT per-range connection/merge overhead.

    Always reports a result (even on failure) with an `ok` flag; the finally block
    guarantees queued batches are flushed and the connection closed on every path,
    so a mid-parse exception can't strand data or leak the client.
    '''
    stats = Source(path)      # stats accumulator across all this worker's ranges
    ok = True
    fail = [False]            # set by a writer thread if it ever drops a batch
    client = None
    writers = []
    work_q = queue.Queue(maxsize=max(1, queue_depth))
    try:
        client = pymongo.MongoClient(
            config['MONGO']['server'], int(config['MONGO']['port']),
            username=config['MONGO']['user'], password=config['MONGO']['pass'])
        coll = client[config['MONGO']['db']].accounts.with_options(
            write_concern=pymongo.write_concern.WriteConcern(w=1))

        writers = [threading.Thread(target=_writer_thread,
                                    args=(coll, source_id, work_q, fail), daemon=True)
                   for _ in range(max(1, write_threads))]
        for w in writers:
            w.start()

        f = File(path)
        f._encoding = encoding                       # skip per-worker libmagic

        while True:
            task = task_q.get()
            if task is None:                         # sentinel: no more ranges
                break
            start, end = task
            lines = f.iter_lines_range(start, end)
            parser = SmartParse(f, presniff=presniff, line_source=lines)
            batch = []
            for account in parser:
                doc = account.document
                doc['s'] = [source_id]
                batch.append(doc)
                stats.increment(account)
                if len(batch) >= batch_size:
                    _put_live(work_q, batch, writers)
                    batch = []
            if batch:
                _put_live(work_q, batch, writers)
            with done_bytes.get_lock():              # coarse progress (per range)
                done_bytes.value += (end - start)
    except Exception as e:                           # never wedge the parent
        ok = False
        import traceback
        log.error(f'worker {idx} failed: {e}\n{traceback.format_exc()}')
    finally:
        # ALWAYS drain: stop + join the writers so queued batches are flushed,
        # then close the connection — on the happy path and every error path.
        try:
            for _ in writers:
                work_q.put(None)
            for w in writers:
                w.join(timeout=_WRITE_RETRY_SECONDS + 60)
                if w.is_alive():
                    ok = False
        except Exception:
            ok = False
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
        if fail[0]:
            ok = False
        result_q.put(_serialize_stats(stats, ok))


def _serialize_stats(s, ok=True):
    '''partial per-source stats, trimmed for cheap IPC back to the parent'''
    return {
        'ok': bool(ok),
        'total_accounts': s.total_accounts,
        'login_types': dict(s.login_types),
        'phone_count': s.phone_count,
        'with_password': s.with_password,
        'with_hash': s.with_hash,
        'with_service': s.with_service,
        'domains': _topk(s.domains, _RETURN_TOPK_HOST),
        'services': _topk(s.services, _RETURN_TOPK_HOST),
        'email_tlds': _topk(s.email_tlds, _RETURN_TOPK_TLD),
        'service_tlds': _topk(s.service_tlds, _RETURN_TOPK_TLD),
        'password_basewords': _topk(s.password_basewords, _RETURN_TOPK_WORD),
        'misc_basewords': _topk(s.misc_basewords, _RETURN_TOPK_WORD),
        'passwords': _topk(s.passwords, _RETURN_TOPK_WORD),
        'password_lengths': dict(s.password_lengths),
    }


def merge_stats_into_source(source, partials):
    '''fold every worker's partial stats back into the real Source object, so the
    final add_source() writes histograms identical to a single-threaded parse.'''
    for r in partials:
        source.total_accounts += r['total_accounts']
        for k in ('email', 'username', 'phone'):
            source.login_types[k] = source.login_types.get(k, 0) + r['login_types'].get(k, 0)
        source.phone_count += r['phone_count']
        source.with_password += r['with_password']
        source.with_hash += r['with_hash']
        source.with_service += r['with_service']
        for k, v in r['domains'].items():
            source.domains.bump(k, v)
        for k, v in r['services'].items():
            source.services.bump(k, v)
        for k, v in r['email_tlds'].items():
            source.email_tlds.bump(k, v)
        for k, v in r['service_tlds'].items():
            source.service_tlds.bump(k, v)
        for k, v in r['password_basewords'].items():
            source.password_basewords.bump(k, v)
        for k, v in r['misc_basewords'].items():
            source.misc_basewords.bump(k, v)
        for k, v in r.get('passwords', {}).items():
            source.passwords.bump(k, v)
        for k, v in r.get('password_lengths', {}).items():
            source.password_lengths[int(k)] = source.password_lengths.get(int(k), 0) + int(v)
    return source


def compute_ranges(size, nworkers):
    '''n contiguous byte ranges tiling [0, size)'''
    if nworkers < 1:
        nworkers = 1
    step = max(1, size // nworkers)
    ranges = []
    off = 0
    for i in range(nworkers):
        end = size if i == nworkers - 1 else min(size, off + step)
        if off < end:
            ranges.append((off, end))
        off = end
    return ranges


class _FormatHolder:
    '''stand-in for source.parser so add_source() can read .format in parallel mode'''
    def __init__(self, fmt):
        self.format = fmt


def can_parallelize(file, presniff):
    '''
    Parallel-split only plain, uncompressed, seekable, utf-8/ascii text in a
    line-independent format with no SQL-INSERT scaffolding.  Everything else
    (multi-line 'blocks', compressed, utf-16/32, SQL dumps) takes the serial path,
    which byte-range splitting cannot reproduce:
      * SQL dumps are split statefully across lines by File.__iter__ — a byte
        range would drop/mangle the INSERT rows and diverge from serial output;
      * utf-16/32 use 0x0A inside multibyte chars, so splitting on newline bytes
        is meaningless; the serial text codec handles them correctly.
    '''
    fmt = presniff.get('format')
    if fmt not in SmartParse.PARALLEL_SAFE_FORMATS:
        return False, f'format {fmt!r} is not line-independent'
    try:
        mt = (file.magic_type or '').lower()
    except Exception:
        mt = ''
    for bad in ('gzip', 'zip', 'bzip2', 'xz', '7-zip', 'compress', 'archive', 'lzma', 'zstandard'):
        if bad in mt:
            return False, f'compressed/container file ({mt})'
    try:
        enc = (file.encoding or '').lower().replace('-', '')
    except Exception:
        enc = ''
    if enc not in ('utf8', 'usascii', 'ascii', ''):
        return False, f'non-utf8 encoding ({enc}) needs the serial text codec'
    # SQL dumps: File.__iter__ turns an "INSERT INTO ... VALUES (...),(...);" into
    # per-row records statefully; detect one in the head and keep it serial.
    try:
        with open(str(file), 'rb') as fh:
            head = fh.read(262144)
        if b'insert into' in head.lower():
            return False, 'SQL INSERT dump (needs stateful row splitting)'
    except OSError:
        pass
    return True, ''


def run_parallel_ingest(source, nworkers, presniff, encoding, batch_size=5000,
                        progress_cb=None, poll=0.25, write_threads=2, queue_depth=4,
                        chunk_factor=8):
    '''
    Run `nworkers` persistent workers against a shared queue of fine-grained byte
    ranges (nworkers * chunk_factor of them), drive a live progress callback, and
    return the list of partial stats dicts.  `source.id` must already be assigned.
    The finer ranges let a worker that drew a light (banner-heavy) slice steal the
    next one instead of idling, so the cores stay saturated to the end.
    '''
    path = str(source.file)
    size = source.file.size
    ranges = compute_ranges(size, max(1, nworkers * max(1, chunk_factor)))
    task_q = Queue()
    for r in ranges:
        task_q.put(r)
    for _ in range(nworkers):
        task_q.put(None)                 # one sentinel per worker

    done_bytes = Value('q', 0)
    result_q = Queue()
    procs = []
    for idx in range(nworkers):
        p = Process(target=_pool_worker,
                    args=(idx, path, encoding, presniff, source.id, batch_size,
                          task_q, result_q, done_bytes, write_threads, queue_depth),
                    daemon=False, name=f'ingest-{idx}')
        p.start()
        procs.append(p)

    def _drain():
        try:
            while True:
                partials.append(result_q.get_nowait())
        except Exception:
            pass

    partials = []
    while len(partials) < nworkers:
        _drain()
        if progress_cb is not None:
            try:
                progress_cb(done_bytes.value)
            except Exception:
                pass
        if len(partials) < nworkers:
            # robustness: if every worker has exited but we're still short a
            # result, a worker died (OOM / SIGKILL) without reporting — don't
            # hang the import forever; finish with the partial stats we have.
            if all(not p.is_alive() for p in procs):
                _drain()
                if len(partials) < nworkers:
                    log.error(f'{nworkers - len(partials)} ingest worker(s) exited '
                              f'without reporting; per-source stats may be incomplete')
                    break
            sleep(poll)

    for p in procs:
        p.join()
    if progress_cb is not None:
        progress_cb(size)

    # the import is COMPLETE only if every worker reported AND every worker
    # finished cleanly (ok) — a missing/!ok worker means some byte range was not
    # fully written, so the caller must not mark the source import_finished=True.
    all_ok = (len(partials) == nworkers and all(p.get('ok', False) for p in partials))
    if not all_ok:
        bad = [p.get('exitcode') for p in procs if p.exitcode]
        log.error(f'parallel ingest incomplete: {len(partials)}/{nworkers} workers '
                  f'reported, {sum(1 for p in partials if not p.get("ok"))} flagged '
                  f'failure (dead exitcodes: {bad}) — source will be left unfinished')
    return partials, all_ok
