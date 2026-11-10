#!/usr/bin/env python3
"""
Benchmark each credshed search dimension against the live database and report
whether MongoDB served it from an index (IXSCAN) or a full collection scan
(COLLSCAN), plus wall-clock timing.

Build the secondary indexes first for a representative result:
    <venv>/bin/python credshed-cli.py --build-indexes

Usage:
    <venv>/bin/python tools/benchmark.py
"""
import logging
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
logging.getLogger('credshed').setLevel(logging.ERROR)
from lib.credshed import CredShed       # noqa: E402
from lib.account import Account         # noqa: E402

cs = CredShed()


def plan_kind(query):
    """return ('IXSCAN'|'COLLSCAN'|..., index_name) for a query"""
    try:
        ex = cs.db.accounts.find(query).explain()
        qp = ex.get('queryPlanner', {}).get('winningPlan', {})

        def walk(stage):
            stages = []
            s = stage
            while s:
                stages.append(s.get('stage'))
                if s.get('stage') == 'IXSCAN':
                    return stages, s.get('indexName')
                nxt = s.get('inputStage')
                ins = s.get('inputStages')
                if ins:  # OR / merge
                    for sub in ins:
                        st, name = walk(sub)
                        if 'IXSCAN' in st:
                            return stages + st, name
                    return stages, None
                s = nxt
            return stages, None

        stages, idx = walk(qp)
        if 'IXSCAN' in stages:
            return 'IXSCAN', idx
        if 'COLLSCAN' in stages:
            return 'COLLSCAN', None
        return '/'.join(s for s in stages if s), idx
    except Exception as e:
        return f'explain-error: {str(e)[:40]}', None


def probe(filt, proj):
    # cheap sampling: first matching doc (fields are common enough that this
    # returns almost immediately; $sample-after-$match would full-scan).
    return cs.db.accounts.find_one(filt, proj)


def timed(fn):
    t = time.time()
    try:
        r = fn()
    except Exception as e:
        return f'>{str(e)[:12]}', (time.time() - t) * 1000
    return r, (time.time() - t) * 1000


CAP_MS = 8000  # don't let a broad count hang the benchmark


def capped_count(q):
    # exact count, but bounded; broad regex counts on millions of rows are slow
    return cs.db.accounts.count_documents(q, maxTimeMS=CAP_MS)


def main():
    total = cs.db.account_count()
    print(f'DB: {total:,} accounts   indexes: {cs.db.index_info()}\n')
    print(f'{"search type":16} {"plan":9} {"index":9} {"count":>10} {"count_ms":>9} {"fetch_ms":>9}  term')
    print('-' * 92)

    cases = []
    # email
    d = probe({'e': {'$exists': True}}, {'e': 1})
    acc = Account.from_document(cs.db.accounts.find_one({'_id': d['_id']}))
    cases.append(('email', acc.email, 'email'))
    cases.append(('domain', acc.domain, 'domain'))
    cases.append(('tld/zone', '.' + acc.domain.rsplit('.', 1)[-1], 'tld'))
    d = probe({'u': {'$exists': True}}, {'u': 1})
    if d:
        cases.append(('username', d['u'], 'username'))
    d = probe({'p': {'$exists': True}}, {'p': 1})
    if d:
        cases.append(('password', d['p'], 'password'))
    d = probe({'t': {'$exists': True}}, {'t': 1})
    if d:
        cases.append(('phone', d['t'], 'phone'))
    d = probe({'v': {'$exists': True}}, {'v': 1})
    if d:
        cases.append(('service', d['v'][::-1], 'service'))
        cases.append(('service-zone', '.' + d['v'][::-1].rsplit('.', 1)[-1], 'service'))

    from lib import validation
    for label, term, qt in cases:
        try:
            q = cs.db._build_query(term, qt)
        except Exception as e:
            print(f'{label:16} build-error: {e}')
            continue
        kind, idx = plan_kind(q)
        cnt, cms = timed(lambda: capped_count(q))
        _, fms = timed(lambda: list(cs.db.accounts.find(q).limit(25).max_time_ms(CAP_MS)))
        cnt_str = f'{cnt:,}' if isinstance(cnt, int) else str(cnt)
        print(f'{label:16} {kind:9} {str(idx or "-"):9} {cnt_str:>12} {cms:>8.0f}ms {fms:>8.1f}ms  {str(term)[:26]}')

    print('\nRegional statistics (from per-source histograms, never scans accounts):')
    _, ms = timed(lambda: cs.db.region_stats(target='email'))
    print(f'  region_stats(email)   {ms:8.1f} ms')
    _, ms = timed(lambda: cs.db.tld_stats(target='service'))
    print(f'  tld_stats(service)    {ms:8.1f} ms')


if __name__ == '__main__':
    main()
