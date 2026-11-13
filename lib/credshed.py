#!/usr/bin/env python3

# by TheTechromancer

import logging
from .db import DB
from .errors import *
from .source import *
from .parser import build_presniff_from_spec
from time import sleep


# set up logging
log = logging.getLogger('credshed')



class CredShed():
    '''
    Main class for interacting with credshed
    Contains useful methods such as:
        .search()
        .import_file()
        ...
    '''

    def __init__(self):

        self._db = None


    @property
    def db(self):

        if self._db is None:
            self._db = DB()
        return self._db
    


    def search(self, query, query_type='email', limit=0):
        '''
        query = search string(s)
        yields Account objects
        '''

        for account in self.db.search(str(query), query_type=query_type, limit=limit):
            #print('{}:{}@{}:{}:{}'.format(result['username'], result['email'], result['domain'], result['password'], result['misc']))
            yield account


    def count(self, query, query_type='email'):

        return self.db.count(query, query_type)


    def db_stats(self):

        return self.db.stats(accounts=True, sources=True, db=True)


    def drop(self):

        self.db.drop()


    def query_stats(self, query, query_type='domain', limit=100):

        # go get the raw data (source_id: num_accounts)
        stats = self.db.query_stats(query, query_type)
        # sort and truncate it
        stats = sorted(stats.items(), key=lambda x: x[1], reverse=True)[:limit]

        return stats


    # DFIR enhancement passthroughs
    def tld_stats(self, target='email', limit=None):
        return self.db.tld_stats(target=target, limit=limit)

    def region_stats(self, target='email'):
        return self.db.region_stats(target=target)

    def source_detail(self, source_id, top_n=2000, zones_top=3000):
        return self.db.source_detail(source_id, top_n=top_n, zones_top=zones_top)

    def build_indexes(self, fields=None):
        return self.db.build_indexes(fields)

    def ensure_indexes(self):
        return self.db.ensure_indexes()

    def drop_indexes(self):
        return self.db.drop_secondary_indexes()


    def get_source(self, source_id):

        return self.db.get_source(source_id)


    def delete_source(self, source_id):

        self.db.delete_source(int(source_id))



    def preview_file(self, filename, limit=20000, format_spec=None, format_delim=None):
        '''
        DFIR triage: parse up to `limit` accounts from a file and return a stats
        summary + sample records WITHOUT writing anything to the database, so an
        investigator can see a file's format and content before ingesting it.
        '''
        presniff = None
        if format_spec:
            presniff = build_presniff_from_spec(format_spec, delimiter=format_delim)
        source = Source(filename)
        source.parse(unattended=True, presniff=presniff)
        samples = []
        for account in source:
            if len(samples) < 25:
                samples.append(account)
            if source.total_accounts >= limit:
                break
        return {
            'file': str(source.file),
            'size': source.file.size,
            'format': getattr(source.parser, 'format', '?'),
            'delimiter': getattr(source.parser, 'delimiter', None),
            'scanned': source.total_accounts,
            'login_types': dict(source.login_types),
            'with_password': source.with_password,
            'with_hash': source.with_hash,
            'with_service': source.with_service,
            'phone': source.phone_count,
            'top_domains': list(source.top_domains(8).items()),
            'top_services': list(source.top_services(8).items()),
            'samples': samples,
        }


    def import_file(self, filename, unattended=True, force=False, stdout=False, force_ascii=False,
                    format_spec=None, format_delim=None, workers=1):
        '''
        Takes a filename as input
        Returns a Source() object containing stats such as total accounts

        Source(filename) --> Source.parse() --> db.add_accounts(source)

        format_spec: optional custom column layout (e.g. "service:email:password")
                     that overrides auto-detection; format_delim overrides the
                     data delimiter.  workers>1 enables parallel single-file ingest.
        '''

        log.info(f'Parsing file "{filename}"')

        start_time = datetime.now()

        presniff = None
        if format_spec:
            presniff = build_presniff_from_spec(format_spec, delimiter=format_delim)
            log.info(f'Using custom format spec -> {presniff["column_map"]} '
                     f'(delimiter {presniff["delimiter"]!r})')

        source = Source(filename)
        # make sure the file is readable
        if unattended and not stdout:
            try:
                source.hash
            except FilestoreHashError:
                log.error(f'Failure reading {filename}')
                return (0, 0)

        source.parse(unattended=unattended, force_ascii=force_ascii, presniff=presniff)

        if stdout:
            for account in source:
                print(str(account))

        else:

            try:
                self.db.add_accounts(source, force=force, workers=workers)

            except KeyboardInterrupt:
                if unattended:
                    raise
                else:
                    log.info(f'Skipping {filename}')
                    try:
                        sleep(1)
                    except KeyboardInterrupt:
                        log.info(f'Cancelling import')
                        raise
                    return (0, 0)


        end_time = datetime.now()
        time_elapsed = (end_time - start_time).total_seconds()

        if source.total_accounts > 0:
            log.info('{:,}/{:,} ({:.2f}%) new accounts in "{}"  Time elapsed: {:02d}:{:02d}:{:02d}'.format(
                source.unique_accounts,
                source.total_accounts,
                ((source.unique_accounts / source.total_accounts) * 100), 
                filename,
                # // == floor division
                int(time_elapsed // 3600),
                int((time_elapsed % 3600) // 60),
                int(time_elapsed % 60)
            ))

        return (source.unique_accounts, source.total_accounts)
