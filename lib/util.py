# by TheTechromancer

### MISC FUNCTIONS USED THROUGHOUT THE CODEBASE ###

import sys
import logging
from .errors import *
from time import sleep
from . import filestore
from pathlib import Path

log = logging.getLogger('credshed.util')


class BoundedCounter(dict):
    '''
    A counting dict that caps the number of distinct keys so that ingesting a
    huge file (e.g. a 250 GB dump with tens of millions of distinct domains /
    services) cannot exhaust RAM.  When the cap is reached it prunes the
    lowest-count (long-tail) keys, keeping the heavy hitters that actually
    matter for top-N / regional statistics.  Counts for surviving keys stay
    exact; only the rarely-seen tail is approximate.
    '''

    __slots__ = ('cap', '_prunes')

    def __init__(self, cap=500000):
        super().__init__()
        self.cap = cap
        self._prunes = 0

    def bump(self, key, n=1):
        if not key:
            return
        if key in self:
            self[key] += n
        elif len(self) < self.cap:
            self[key] = n
        else:
            self._prune()
            # after pruning there is room again; a brand-new tail key is
            # dropped (not counted) only in the rare case the prune freed nothing
            if len(self) < self.cap:
                self[key] = n

    def _prune(self):
        # keep the top half by count; drops the long tail
        self._prunes += 1
        keep = sorted(self.items(), key=lambda kv: kv[1], reverse=True)[: max(1, self.cap // 2)]
        self.clear()
        self.update(keep)


def encode(s):

    try:
        return s.encode(encoding='utf-8')
    except UnicodeEncodeError:
        return ''


def decode(b):

    try:
        return b.decode(encoding='utf-8')
    except UnicodeDecodeError:
        return str(b)[2:-1]


def errprint(*s, end='\n'):

    sys.stderr.write(' '.join([str(i) for i in s]) + end)
    sys.stderr.flush()


def error_detail(e):
    '''
    Given a pymongo error, returns a string containing as much detail as possible
    '''
    error = f'{e}: '
    try:
        error += str(e.details)
    except AttributeError:
        pass
    return error


def number_range(s):
    '''
    takes array of strings and tries to convert into an array of ints
    '''

    n_array = set()

    for a in s:
        for r in a.split(','):
            try:
                if '-' in r:
                    start, end = [int(i) for i in r.split('-')[:2]]
                    n_array = n_array.union(set(list(range(start, end+1))))
                else:
                    n_array.add(int(r))

            except (IndexError, ValueError):
                sys.stderr.write('[!] Error parsing source ID "{}"'.format(a))
                continue

    return n_array


def recursive_file_list(paths, min_size=6):
    '''
    accepts single or multiple files/directories
    yields file objects
    '''

    if not type(paths) == list:
        paths = [paths]

    paths = [Path(p).resolve() for p in paths]

    for path in paths:

        log.info(f'Finding files in {path}')
        files = list(filestore.util.list_files(path))
        log.info(f'Found {len(files):,} files in {path}')

        average_file_size = bytes_to_human(sum([file.size for file in files]) / len(files))
        log.info(f'Average file size: {average_file_size}')

        for i, file in enumerate(files):

            # check size
            if file.size < min_size:
                log.debug(f'Skipping tiny/empty file "{file}"')
                continue

            yield file


def bytes_to_human(_bytes):
    '''
    converts bytes to human-readable filesize
    e.g. 1024 --> 1KB
    '''

    sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB']
    units = {}
    count = 0
    for size in sizes:
        units[size] = pow(1024, count)
        count +=1

    for size in sizes:
        if abs(_bytes) < 1024.0:
            if size == sizes[0]:
                _bytes = str(int(_bytes))
            else:
                _bytes = '{:.2f}'.format(_bytes)
            return '{}{}'.format(_bytes, size)
        _bytes /= 1024

    raise ValueError



class FileLock:
    '''
    Implements a simple sempahore using the filesystem
    '''
    def __init__(self, name='/tmp/credshed.lock'):

        self.file = Path(name).resolve()
        self.interval = .1


    def __enter__(self):

        while 1:
            if not self.file.is_file():
                with open(self.file, 'w') as f:
                    break
            else:
                sleep(self.interval)
                continue

        return self


    def __exit__(self, exception_type, exception_value, traceback):

        self.file.unlink()
