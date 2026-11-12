import os
import magic
import hashlib
import pathlib
from ..errors import *


class File(type(pathlib.Path())):
    '''
    Given a filename, yield decoded lines
    '''

    default_encoding = 'utf-8'

    # NOTE: Python 3.12 reworked pathlib so the old __new__-based construction
    # (passing a pre-built path into cls()) collapses the path to '.'.  We now
    # resolve in __init__ and use with_segments() so pathlib's own derivations
    # (parent, relative_to, iterdir, ...) don't get re-resolved.
    def __init__(self, *args, parse=True, _resolve=True):

        if args and _resolve:
            try:
                super().__init__(str(pathlib.Path(*args).resolve()))
            except (OSError, ValueError, TypeError):
                super().__init__(*args)
        else:
            super().__init__(*args)

        self._magic_type = None
        self._encoding = None
        self._size = None
        self._parse = parse

        self._hashes = dict()

    def with_segments(self, *pathsegments):
        # used internally by pathlib to build derived paths; keep them raw
        return type(self)(*pathsegments, _resolve=False)


    @property
    def encoding(self):

        if self._encoding is None:
            self._read_magic()
        return self._encoding


    @property
    def magic_type(self):

        if self._magic_type is None:
            self._read_magic()
        return self._magic_type


    @property
    def head(self):

        try:
            with open(self, 'rb') as f:
                # read 4KB
                _head = f.read(4 * 1024)
        except OSError as e:
            raise FileReadError(e)

        return _head


    @staticmethod
    def sql_split_insert(line):
        '''
        Takes all or part of an INSERT statement and yields each SQL row separately
        '''

        sql_end = False
        row = []
        for i in range(len(line)):
            char = line[i]
            # just split on all parenthesis
            if char in ('(', ')', ';'):
                if row:
                    yield ''.join(row).replace('NULL', '')
                    row = []
                if char == ';':
                    sql_end = True
            else:
                row.append(char)

        if row:
            yield ''.join(row).replace('NULL', '')
        if sql_end:
            yield False


    def hash(self, algo='sha1', blocksize=65536):
        '''
        creates a SHA1 and MD5 hash in one go
        '''

        algo = algo.strip().lower()

        try:
            filehash = self._hashes[algo]
            log.debug(f'Hash for {self} already calculated')
            return filehash

        except KeyError:

            log.info(f'Computing hash for {self}')
            md5 = hashlib.md5()
            sha1 = hashlib.sha1()

            try:
                with open(str(self), 'rb') as f:
                    block = f.read(blocksize)
                    while len(block) > 0:
                        sha1.update(block)
                        md5.update(block)
                        block = f.read(blocksize)

                md5_hash = md5.hexdigest()
                self._hashes['md5'] = md5_hash
                sha1_hash = sha1.hexdigest()
                self._hashes['sha1'] = sha1_hash

                log.debug(f'Successfully hashed file {self}')

            except OSError as e:
                raise FileHashError(f'Failed to hash file {self}: {e}')

        return self._hashes[algo]
    

    def _read_magic(self):

        log.debug(f'Running libmagic on {self}')

        head = self.head

        # get magic type
        if self._magic_type is None:
            try:
                self._magic_type = magic.from_buffer(head)
            except magic.MagicException as e:
                log_error(e)
                self._magic_type = 'data'
            log.debug(f'Magic type of {self} is {self._magic_type}')

        # get encoding
        if self._encoding is None:
            # detect encoding with libmagic
            m = magic.Magic(mime_encoding=True)
            try:
                self._encoding = m.from_buffer(head)
            except magic.MagicException as e:
                self._encoding = 'binary'

            # fall back to utf-8 if encoding can't be detected
            if self._encoding == 'binary' or self._encoding.endswith('ascii'):
                self._encoding = self.default_encoding
            log.debug(f'Encoding of {self} is {self._encoding}')


    def _read_file(self):
        '''
        Tries to decode by magic type and falls back to ascii
        '''

        decoding_errors = 0

        # cap on a single read so a file with no (or extremely sparse) newlines
        # streams in bounded chunks instead of loading 250 GB into one string
        max_line = 1 << 20  # 1 MiB

        # read UTF-8 as utf-8-sig so a leading BOM is stripped transparently
        # (and plain UTF-8 still decodes identically)
        enc = self.encoding
        if (enc or '').lower().replace('-', '') in ('utf8', 'usascii', 'ascii'):
            enc = 'utf-8-sig'

        try:
            try:
                self._f = open(self, 'r', encoding=enc, errors='backslashreplace')
            except LookupError:
                self._f = open(self, 'r', encoding=self.default_encoding, errors='backslashreplace')

            # readline(size) returns at most `size` chars OR up to a newline,
            # so an unusually long line is emitted in <=1 MiB pieces rather than
            # buffered whole.  Normal (newline-terminated) lines are unaffected.
            while True:
                line = self._f.readline(max_line)
                if not line:
                    break
                yield line.strip('\r\n\t')

            '''
            while 1:
                # try detected encoding
                try:
                    #log.debug('Splitting lines (string)')
                    for line in f:
                        yield line

                # if that fails, convert to hex notation
                except ValueError as e:

                    log.error(str(e.object)[:40] + ': ' + str(self))
                    #log.error(e)
                    #log.error(e.args)
                    #log_error(e)

                    # this handles an infinite loop bug in Python's unicode libraries
                    if len(e.object) >= 1 and e.object[0] > 127:
                        decoding_errors += 1
                        if decoding_errors > 10000:
                            break
                    else:
                        decoding_errors = 0

                    #log.debug('Splitting lines (bytes)')
                    for line in e.object.splitlines():
                        yield str(line)[2:-1]

                except StopIteration:
                    break
            '''

        finally:
            self._f.close()


    def resolve(self):

        return self


    @property
    def size(self):
        '''
        Returns size of file in bytes
        '''

        if self._size is None:
            try:
                self._size = os.stat(str(self)).st_size
            except OSError as e:
                raise FileSizeError(f'Error getting filesize from {self}: {e}')
        return self._size


    @property
    def bytes_read(self):
        '''
        Bytes consumed so far by the active read (for %-complete / ETA progress).
        Uses the underlying buffered reader's offset; 0 when not currently reading.
        Slightly optimistic (read-ahead), which is fine for a progress indicator.
        '''
        try:
            return min(self._f.buffer.tell(), self.size)
        except (AttributeError, ValueError, OSError):
            return 0


    def _decode_encoding(self):
        '''the text codec used for this file (mirrors _read_file's choice)'''
        enc = self.encoding
        if (enc or '').lower().replace('-', '') in ('utf8', 'usascii', 'ascii'):
            enc = 'utf-8-sig'
        return enc


    def iter_lines_range(self, start, end, progress=None, slot=None, every=4000):
        '''
        DFIR enhancement (parallel ingest): yield decoded, stripped lines whose
        *start* falls in the byte range [start, end).

        Newline-aligned so adjacent ranges tile the file with no overlap and no
        gap: a worker keeps the line beginning at `start` only when the preceding
        byte is a newline (otherwise that partial line belongs to the previous
        range and is skipped), and always finishes the line that straddles `end`.

        Matches _read_file exactly so a parallel parse sees byte-identical lines:
          * readline is capped at 1 MiB, so a pathological no-/sparse-newline file
            (the "250 GB single line" threat model) streams in bounded pieces
            instead of materialising gigabytes in one worker (OOM) — and a >1 MiB
            line is emitted as the same <=1 MiB pieces the serial reader produces;
          * a byte-order mark is stripped only at the very start of the file (as a
            whole-stream utf-8-sig decode would), never from a mid-file line.
        The partial-line skip at `start` is likewise piece-bounded so it can't
        buffer a huge straddling line while discarding it.

        Caller (can_parallelize) guarantees a utf-8/ascii, uncompressed, non-SQL
        file here; utf-16/32 and SQL dumps take the serial path, which decodes via
        a text codec / applies stateful SQL-splitting that byte ranges cannot.
        '''
        MAXL = 1 << 20  # 1 MiB, mirrors _read_file's cap
        enc = self.encoding
        # decode with plain utf-8 (NOT utf-8-sig): a sig codec would strip a BOM on
        # every piece; we strip it once, only at file start, to match the serial path
        dec = 'utf-8' if (enc or '').lower().replace('-', '') in ('utf8', 'usascii', 'ascii') else enc
        strip_bom = (start == 0)
        i = 0

        def publish(pos):
            if progress is not None and slot is not None:
                try:
                    progress[slot] = min(int(pos), end)
                except (IndexError, ValueError, TypeError):
                    pass

        with open(self, 'rb') as f:
            if start > 0:
                f.seek(start - 1)
                if f.read(1) != b'\n':
                    # discard the partial line we begin inside, in bounded pieces
                    while True:
                        c = f.readline(MAXL)
                        if not c or c.endswith(b'\n'):
                            break
            while f.tell() < end:
                # one logical line, emitted in <=MAXL pieces exactly like _read_file
                while True:
                    raw = f.readline(MAXL)
                    if not raw:
                        publish(end)
                        return
                    i += 1
                    if i % every == 0:
                        publish(f.tell())
                    s = raw.decode(dec, errors='backslashreplace')
                    if strip_bom:
                        strip_bom = False
                        if s[:1] == '﻿':
                            s = s[1:]
                    yield s.strip('\r\n\t')
                    if raw.endswith(b'\n'):
                        break
        publish(end)



    def __iter__(self):

        assert self.is_file(), f'Cannot open {self} as file'

        insert_into = 'INSERT INTO'
        sql_insert = False

        try:
            for line in self._read_file():

                if self._parse:
                    # handle SQL INSERT statements
                    if not sql_insert:
                        if line.startswith(insert_into):
                            log.debug(f'SQL INSERT statement detected in {self}')
                            sql_insert = True

                    if sql_insert:
                        for row in self.sql_split_insert(line):
                            if row == False:
                                log.debug(f'End of SQL INSERT statement in {self}')
                                sql_insert = False
                            else:
                                yield row
                    else:
                        yield line
                else:
                    yield line

        except OSError as e:
            log.error(f'Error opening {self}: {e}')