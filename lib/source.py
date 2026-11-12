#!/usr/bin/env python3

# by TheTechromancer

from .util import *
from .errors import *
from .parser import *
from pathlib import Path
from .filestore import *
from .config import config
from datetime import datetime
from .parser.file import File
from . import validation
from . import regions
from .validation import word_regex


# set up logging
log = logging.getLogger('credshed.source')



class Source():
    '''
    Source = a source of data, typically a file.  Deduplicated by file hash, so one source can have multiple files of the same hash

    1. Give it a filename:
        l = Source('dump.txt')
    2. Parse
        l.parse()
    3. Iterate
        for account in l:
            print(account)
    '''


    @classmethod
    def from_doc(cls, doc):
        '''
        Create a Source() object from a dictionary
        '''

        try:
            c = cls(doc.pop('filename'), name=doc.pop('name'), filesize=doc.pop('filesize'))
            #c.update(doc)
            for k,v in doc.items():
                setattr(c,k,v)
            return c
        except (KeyError, IndexError) as e:
            raise CredShedSourceError(f'Failed to create Source object from db: {e}')


    def __init__(self, file, name=None, filesize=None, deduplicate=False):

        # Not set unless retrieved from DB
        self.id = None

        # filename from which accounts are extracted
        self.file = File(file)
        if name is None:
            self.name = str(self.file)
        else:
            self.name = name

        if filesize is not None and self.file._size is None:
            self.file._size = filesize

        # the parser instance (set during parse(); exposes detected format + stats)
        self.parser = None
        # set used for account deduplication
        self._accounts = set()
        # keeps track of total accounts during import
        self.total_accounts = 0
        # how many never-before-seen accounts have been imported (for runtime user feedback only, not stored)
        self.unique_accounts = 0
        # whether or not to deduplicate accounts (collects accounts immediately into memory rather than lazily)
        self.deduplicate = deduplicate
        # description for source
        self.description = ''
        # SHA1 hash of file
        self._hash = None
        # top (email) domains  (bounded so a 250 GB file can't exhaust RAM)
        self.domains = BoundedCounter(500000)
        # top base words from passwords
        self.password_basewords = BoundedCounter(500000)
        # top base words from misc/description field
        self.misc_basewords = BoundedCounter(500000)
        # DFIR/threat-intel: plaintext-password frequency + a length histogram
        # (how weak/strong the population's passwords are) — both cheap to tally.
        # 250k cap keeps the stored top-1000 exact while bounding per-worker RAM.
        self.passwords = BoundedCounter(250000)
        self.password_lengths = {}   # length -> count
        # DFIR enhancement: per-source histograms for fast regional / service stats.
        # Real TLD zones number only a few thousand, so a 500k cap keeps them exact
        # while bounding the memory a flood of malformed "zones" from dirty hosts
        # could otherwise consume; host/baseword counters prune their long tail.
        self.email_tlds = BoundedCounter(500000)     # email-domain zone -> count (victim geography)
        self.services = BoundedCounter(500000)       # breached service host -> count
        self.service_tlds = BoundedCounter(500000)   # service zone -> count
        # login-type + phone tallies
        self.login_types = {'email': 0, 'username': 0, 'phone': 0}
        self.phone_count = 0
        self.with_password = 0
        self.with_hash = 0
        self.with_service = 0



    def parse(self, unattended=True, force_ascii=True, presniff=None):

        if unattended:
            self.description = f'Unattended import at {datetime.now().isoformat(timespec="milliseconds")}'
        else:
            self.description = f'Manual import at {datetime.now().isoformat(timespec="milliseconds")}'

        # DFIR enhancement: use the format-aware, dirty-data-tolerant SmartParse
        # (ULP / combo / CSV / SQL / JSON-lines) instead of the email-only absorber.
        # `presniff` (from build_presniff_from_spec) lets an investigator force a
        # custom column layout instead of auto-detecting it.
        accounts = SmartParse(self.file, unattended=unattended, force_ascii=force_ascii,
                              presniff=presniff)
        self.parser = accounts

        if self.deduplicate:
            for account in accounts:
                self._accounts.add(account)
        else:
            self._accounts = accounts


    @property
    def hash(self):

        if self._hash is None:
            self._hash = self.file.hash()
        return self._hash


    @staticmethod
    def _tally(d, key):
        d.bump(key)

    def increment(self, account):

        self.total_accounts += 1

        if account.domain:
            self.domains.bump(account.domain)
            self.email_tlds.bump(validation.tld_of(account.domain))
            self.login_types['email'] += 1
        elif account.phone:
            self.login_types['phone'] += 1
        elif account.username:
            self.login_types['username'] += 1

        # breached service (ULP "URL" field) + its zone
        if account.service:
            self.with_service += 1
            self.services.bump(account.service)
            self.service_tlds.bump(validation.tld_of(account.service))

        if account.phone:
            self.phone_count += 1
        if account.hashes:
            self.with_hash += 1

        if account.password:
            self.with_password += 1
            self.passwords.bump(account.password)
            L = len(account.password)
            if L <= 128:                       # cap bucket key; longer are outliers
                self.password_lengths[L] = self.password_lengths.get(L, 0) + 1
            for word in validation.basewords_lower(account.password):
                self.password_basewords.bump(word)

        if account.misc:
            for word in validation.basewords_lower(account.misc):
                self.misc_basewords.bump(word)


    def top_domains(self, limit=10):

        sorted_domains = dict(sorted(self.domains.items(), key=lambda x: x[1], reverse=True)[:limit])
        return {d: c for d,c in sorted_domains.items()}


    def top_password_basewords(self, limit=10):

        sorted_words = dict(sorted(self.password_basewords.items(), key=lambda x: x[1], reverse=True)[:limit])
        return {w: c for w,c in sorted_words.items()}


    def top_passwords(self, limit=1000):

        return {p: c for p, c in sorted(self.passwords.items(), key=lambda x: x[1], reverse=True)[:limit]}


    def top_misc_basewords(self, limit=10):

        sorted_words = dict(sorted(self.misc_basewords.items(), key=lambda x: x[1], reverse=True)[:limit])
        return {w: c for w,c in sorted_words.items()}


    def top_services(self, limit=100):

        sorted_services = sorted(self.services.items(), key=lambda x: x[1], reverse=True)[:limit]
        return {s: c for s, c in sorted_services}


    def email_tld_histogram(self, limit=None):
        '''full email-domain zone histogram (victim geography), most common first'''
        items = sorted(self.email_tlds.items(), key=lambda x: x[1], reverse=True)
        if limit:
            items = items[:limit]
        return {t: c for t, c in items}


    def service_tld_histogram(self, limit=None):
        items = sorted(self.service_tlds.items(), key=lambda x: x[1], reverse=True)
        if limit:
            items = items[:limit]
        return {t: c for t, c in items}


    @property
    def progress(self):

        try:
            total = self.file.size
            done = self.file.bytes_read
            pct = (done / total * 100) if total else 0.0
            return f'{self.total_accounts:,} rows ({pct:.1f}% of {bytes_to_human(total)})'
        except (NameError, AttributeError, TypeError, ZeroDivisionError):
            return f'{self.total_accounts:,} rows'


    def __iter__(self):

        for account in self._accounts:
            self.increment(account)
            yield account


    def __str__(self):

        try:
            store_dir = config['FILESTORE']['store_dir']
            filename = self.file.relative_to(store_dir)
        except (KeyError, ValueError):
            filename = self.file

        return f'{filename} (total accounts: {len(self):,})'


    def __len__(self):

        try:
            length = len(self._accounts)
        except TypeError:
            length = 0

        if length > 0:
            return length
        else:
            return self.total_accounts