#!/usr/bin/env python3

# by TheTechromancer

import sys
import math
import logging
import argparse
from lib import logger
from time import sleep
import multiprocessing
from lib.errors import *
from pathlib import Path
import concurrent.futures
from lib.credshed import *
from lib import validation
from lib import regions
from lib.parser import File
from lib.processpool import *
from datetime import datetime
from lib import util as core_util
from lib.filestore import util as filestore_util

# set up logging
log = logging.getLogger('credshed.cli')


def zip_filelist(l):
    '''
    alternates large and small files
    e.g. [1,2,3,4,5] --> [1,5,2,4,3]
    '''

    l.sort(key=lambda x: x.size, reverse=True)
    zipped_filelist = []
    half_len = int(len(l)/2)
    slice1 = l[half_len:]
    slice2 = l[:half_len]
    slice1.sort(key=lambda x: x.size)

    for i in range(half_len+1):
        try:
            zipped_filelist.append(slice1[i])
        except IndexError:
            pass
        try:
            zipped_filelist.append(slice2[i])
        except IndexError:
            pass

    return zipped_filelist



class CredShedCLI(CredShed):

    def __init__(self, options):

        super().__init__()
        self.options = options

    @staticmethod
    def format_account(a):
        '''readable, field-labeled one-line rendering for DFIR triage'''
        parts = []
        if a.email:
            parts.append(a.email)
        if a.username:
            parts.append(f'user={a.username}')
        if a.phone:
            parts.append(f'tel={a.phone}')
        if a.password:
            parts.append(f'pass={a.password}')
        if a.hashes:
            parts.append(f'hash={a.formatted_hashes}')
        if a.service:
            parts.append(f'@ {a.service}')
        if a.misc:
            parts.append(f'misc={a.misc[:80]}')
        if a.sources:
            parts.append(f'src={",".join(str(s) for s in a.sources)}')
        return '  '.join(parts)

    def _emit(self, account):
        if self.options.print0:
            sys.stdout.buffer.write(account.bytes + b'\n')
        elif getattr(self.options, 'json', False):
            import json as _json
            print(_json.dumps(account.json, ensure_ascii=False))
        elif getattr(self.options, 'colons', False):
            print(str(account))
        else:
            print(self.format_account(account))

    def search(self):

        start_time = datetime.now()
        num_accounts_in_db = self.db.account_count()

        # limit == -1 means unlimited
        limit = int(self.options.limit)
        remaining = None if limit < 0 else limit

        num_results = 0
        for keyword in self.options.search:
            if remaining is not None and remaining <= 0:
                break
            try:
                query_type = validation.validate_query_type(keyword, self.options.query_type)
            except CredShedValidationError as e:
                log.error(str(e))
                continue
            log.info(f'Searching by {query_type}: {keyword}')

            per_query_limit = 0 if remaining is None else remaining
            for account in super().search(keyword, query_type=query_type, limit=per_query_limit):
                self._emit(account)
                num_results += 1
                if remaining is not None:
                    remaining -= 1
                    if remaining <= 0:
                        break

        end_time = datetime.now()
        time_elapsed = (end_time - start_time)
        log.info(f'Searched {num_accounts_in_db:,} accounts in {str(time_elapsed)[:-4]} seconds')

        # Report counts WITHOUT a second full scan: for an unlimited search the
        # number returned IS the exact total; for a limited one we only know we
        # hit the cap (show N+), otherwise N is exact.
        hit_limit = (remaining is not None and remaining <= 0)
        count_str = f'{num_results:,}+' if hit_limit else f'{num_results:,}'
        log.info(f'{count_str} results for "{" + ".join(self.options.search)}"')


    def region_stats(self):
        '''--tld-stats / --region-stats : domain-zone + regional breakdown'''
        target = getattr(self.options, 'tld_stats', 'email') or 'email'
        rs = super().region_stats(target=target)
        label = 'EMAIL-DOMAIN (victim geography)' if target == 'email' else 'BREACHED-SERVICE'
        print('=' * 64)
        print(f'  DOMAIN-ZONE / REGIONAL STATISTICS  [{label}]')
        print('=' * 64)
        if not rs['zones']:
            print('  (no data - ingest some sources first)')
            return
        top = rs['regions'][0][1] if rs['regions'] else 1
        print('\n  By region:')
        for region, count in rs['regions']:
            bar = '#' * int(44 * count / max(1, top))
            print(f'    {region:34} {count:>12,}  {bar}')
        print('\n  Top countries (ccTLD):')
        for country, count in rs['countries'][:25]:
            print(f'    {country:34} {count:>12,}')
        print('\n  Top zones (raw TLD):')
        for tld, count in rs['zones'][:25]:
            c, r = regions.region_of(tld)
            tag = f'  ({c})' if c else ''
            print(f'    .{tld:33} {count:>12,}{tag}')
        print()


    def index_ops(self):
        if self.options.drop_indexes:
            dropped = super().drop_indexes()
            log.info(f'Dropped indexes: {dropped}')
        if self.options.build_indexes is not None:
            fields = self.options.build_indexes or None
            built = super().build_indexes(fields)
            log.info(f'Built indexes on fields: {built}')


    def query_stats(self):

        for keyword in self.options.search:
            stats = super().query_stats(keyword)
            log.info(stats)


    def db_stats(self):

        print(super().db_stats())


    def import_file(self, file, options, magic_blacklist=None):
        '''
        mongo seems to crash when importing one of these files:
            - "/mnt/synology_4bay/extracted/auto/bigDB.torrent/Database Collection/1.txt"
            - "/mnt/synology_4bay/extracted/auto/bigDB.torrent/Trading Collection/123к.txt"
            - "/mnt/synology_4bay/extracted/auto/bigDB.torrent/BTC Collection/20 (1).txt"
            - "/mnt/synology_4bay/extracted/auto/bigDB.torrent/BTC Collection/5 (2).txt"
            - "/mnt/synology_4bay/extracted/auto/bigDB.torrent/BTC Collection/21 (1).txt"
            - "/mnt/synology_4bay/extracted/auto/bigDB.torrent/BTC Collection/19 (1).txt"
            - "/mnt/synology_4bay/extracted/auto/bigDB.torrent/bigDB"
            - "/mnt/synology_4bay/extracted/auto/bigDB.torrent/Region Specific Collection/RU/RU (1).txt"
            - "/mnt/synology_4bay/extracted/auto/bigDB.torrent/BTC Collection/9 (1).txt"
            - "/mnt/synology_4bay/extracted/auto/bigDB.torrent/UPDATES/#5 November 17th 2018/Region Specific/ 2018-11-17 08-04-33[.ru].txt"

            - "/mnt/synology_4bay/extracted/auto/Collection #2-#5 & Antipublic.torrent/AP MYR & ZABUGOR #2_EU + RUSSIAN ANTIPUBLIC.tar.gz.extracted/AP MYR & ZABUGOR #2_EU + RUSSIAN ANTIPUBLIC/5.txt"
            - "/mnt/synology_4bay/extracted/auto/Collection #2-#5 & Antipublic.torrent/Collection #2_New combo cloud_Trading Collection.tar.gz.extracted/Collection #2_New combo cloud_Trading Collection/123к.txt"
            - "/mnt/synology_4bay/extracted/auto/Collection #2-#5 & Antipublic.torrent/AP MYR & ZABUGOR #2_EU + RUSSIAN ANTIPUBLIC.tar.gz.extracted/AP MYR & ZABUGOR #2_EU + RUSSIAN ANTIPUBLIC/19.txt"
            - "/mnt/synology_4bay/extracted/auto/Collection #2-#5 & Antipublic.torrent/Collection #2_New combo cloud_Streaming Collection.tar.gz.extracted/Collection #2_New combo cloud_Streaming Collection/Private_merge.txt"
            - "/mnt/synology_4bay/extracted/auto/Collection #2-#5 & Antipublic.torrent/Collection #2_New combo cloud_UPDATES_November 4th 2018_Update Dumps.tar.gz.extracted/Collection #2_New combo cloud_UPDATES_November 4th 2018_Update Dumps/rkpsorioin.yhteystietopalvelu.com {3.737} [HASH+NOHASH].rar.extracted/Rejected.txt"

        '''

        try:

            if magic_blacklist is None:
                magic_blacklist = [
                    # PNG, JPEG, etc.
                    'image data',
                    # ZIP, GZ, etc.
                    'archive data',
                    # encrypted data
                    'encrypted'
                ]

            # check magic type
            magic_type = file.magic_type.lower()

            if any([x in magic_type for x in magic_blacklist]):
                log.debug(f'Skipping file of type "{file.magic_type}"')

            else:

                return super().import_file(
                    file,
                    unattended=options.unattended,
                    force=options.force_ingest,
                    stdout=options.stdout,
                    force_ascii=False
                )

        except KeyboardInterrupt:
            log.critical('Interrupted')

        except FileError as e:
            log.warning(str(e))

        return (0,0)


    def import_files(self):
        '''
        benchmark for full /etc import (1,500 files):
            3 process, main thread: 2:13
            3 processes: 1:27
        '''

        total_accounts = 0
        unique_accounts = 0

        # total number of files processed
        processed_files = 0
        # number of files that contained at least one account
        interesting_files = 0

        major_start_time = datetime.now()

        # make a list of all files (excluding compressed ones)
        filelist = list(set(core_util.recursive_file_list(self.options.ingest)))
        total_file_count = len(filelist)
        log.info(f'Importing a total of {len(filelist):,} files')

        # alternate large and small files
        filelist = zip_filelist(filelist)
        #filelist.sort(key=lambda x: x.size, reverse=True)
        #import random
        #random.shuffle(filelist)


        # if unattended, spawn processes like there's no tomorrow
        if self.options.unattended:

            # ensure total number of threads stay consistent
            #if large_files:
            log.info(f'Importing {len(filelist):,} files using {self.options.threads:,} file threads')

            with ProcessPool(self.options.threads, name='Import') as pool:
                for unique, total in pool.map(self.import_file, filelist, (self.options,)):
                    processed_files += 1
                    if total > 0:
                        interesting_files += 1
                    unique_accounts += unique
                    total_accounts += total

                    progress_time = datetime.now()
                    time_elapsed = (progress_time - major_start_time).total_seconds()
                    log.info(
                        'Imported {:,}/{:,}/{:,} files in {:02d}:{:02d}:{:02d}'.format(
                            interesting_files,
                            processed_files,
                            total_file_count,
                            int(time_elapsed // 3600),
                            int((time_elapsed % 3600) // 60),
                            int(time_elapsed % 60)
                        )
                    )

        else:
            for file in filelist:
                unique, total = self.import_file(file, self.options)

                processed_files += 1
                if total > 0:
                    interesting_files += 1
                unique_accounts += unique
                total_accounts += total

                progress_time = datetime.now()
                time_elapsed = (progress_time - major_start_time).total_seconds()
                log.info(
                    'Imported {} in {:02d}:{:02d}:{:02d}'.format(
                        str(file),
                        int(time_elapsed // 3600),
                        int((time_elapsed % 3600) // 60),
                        int(time_elapsed % 60)
                    )
                )


        end_time = datetime.now()
        time_elapsed = (end_time - major_start_time).total_seconds()

        log.info('{:,}/{:,} unique accounts from {:,}/{:,} files in {:02d}:{:02d}:{:02d}'.format(
            unique_accounts,
            total_accounts,
            interesting_files,
            len(filelist),
            int(time_elapsed // 3600),
            int((time_elapsed % 3600) // 60),
            int(time_elapsed % 60)
        ))



    def delete_leak(self):
        
        try:

            if self.options.delete_leak:

                to_delete = {}
                for source_id in number_range(self.options.delete_leak):
                    source_info = (self.db.get_source(source_id))
                    if source_info is not None:
                        to_delete[source_id] = str(source_id) + ': ' + str(source_info)

                if to_delete:
                    errprint('\nDeleting accounts from:\n\t{}'.format('\n\t'.join(to_delete.values())), end='\n\n')
                    if not input('OK? [Y/n] ').lower().startswith('n'):
                        start_time = datetime.now()

                        log.debug(errprint('Deleting accounts from: {}'.format(', '.join(to_delete.values()))))

                        for source_id in to_delete:
                            self.delete_leak(source_id)

                        end_time = datetime.now()
                        time_elapsed = (end_time - start_time)

                        errprint('\nDeletion finished.  Time Elapsed: {}'.format(str(time_elapsed).split('.')[0]))
                        log.debug('Deletion of {} finished.  Time Elapsed: {}\n'.format(', '.join(to_delete.values()), str(time_elapsed).split('.')[0]))
                else:
                    log.warning('No valid leaks specified were specified for deletion')

            else:

                while 1:

                    assert self.db.sources.estimated_document_count() > 0, 'No more leaks in DB'
                    self.db.stats()
                    highest_source_id = self.db.highest_source_id()

                    try:
                        to_delete = [input(f'Enter ID(s) to delete [{highest_source_id}] (CTRL+C when finished): ')] or [highest_source_id]
                    except ValueError:
                        errprint('[!] Invalid entry', end='\n\n')
                        sleep(1)
                        continue

                    self.delete_leak(to_delete)


        except KeyboardInterrupt:
            errprint('\n[*] Deletion cancelled')
            sys.exit(1)



def main(options):

    try:

        try:
            credshed = CredShedCLI(options)
        except CredShedError as e:
            log.critical('{}: {}\n'.format(e.__class__.__name__, str(e)))
            sys.exit(1)

        # if we're importing stuff
        try:
            if options.drop:
                log.critical('--drop DELETES ALL DATA FROM THE DATABASE')
                log.critical('Press CTRL+C within 5 seconds to cancel')
                sleep(5)
                credshed.drop()

            if options.ingest:
                credshed.import_files()

            elif options.delete_leak is not None:
                credshed.delete_leak()

            elif options.search:
                credshed.search()

            # DFIR enhancement operations
            if options.build_indexes is not None or options.drop_indexes:
                credshed.index_ops()

            if options.tld_stats:
                credshed.region_stats()

            if options.db_stats:
                credshed.db_stats()

        except (KeyboardInterrupt, BrokenPipeError):
            log.critical('Interrupted')
            credshed.STOP = True

        except AssertionError as e:
            log.critical(e)
            sys.exit(2)

        except CredShedError as e:
            log.error('{}: {}\n'.format(e.__class__.__name__, str(e)))

    except KeyboardInterrupt:
        log.critical('Interrupted')

    except Exception as e:
        import traceback
        log.critical(traceback.format_exc())
        


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    num_cores = multiprocessing.cpu_count()
    default_threads = min(6, max(2, int(num_cores)))

    parser.add_argument('search',                       nargs='*',                      help='search term(s)')
    parser.add_argument('-q', '--query-type',           default='auto',                 help='query type: email, domain, tld/zone, username, password, phone, service (auto-detected by default)')
    parser.add_argument('--tld-stats', nargs='?', const='email', choices=['email', 'service'], metavar='TARGET',
                                                                                        help='show domain-zone / regional statistics (email=victim geography [default], service=breached platform)')
    parser.add_argument('--build-indexes', nargs='*', metavar='FIELD',                  help='build secondary search indexes then exit (fields: u p t v; default all). Run after a bulk ingest.')
    parser.add_argument('--drop-indexes', action='store_true',                          help='drop secondary search indexes (faster bulk ingest)')
    parser.add_argument('--json', action='store_true',                                  help='output search results as JSON lines')
    parser.add_argument('--colons', action='store_true',                                help='output results in legacy colon format (email:user:pass:hash:misc:phone:service)')
    parser.add_argument('-i', '--ingest',   type=Path,  nargs='+',                      help='import files or directories into the database')
    parser.add_argument('-f', '--force-ingest',         action='store_true',            help='also ingest files which have already been imported')
    parser.add_argument('-db', '--db-stats', action='store_true',                       help='show all imported leaks and DB stats')
    parser.add_argument('-s', '--stdout',   action='store_true',                        help='when importing, write to stdout instead of database (null-byte delimited, use tr \'\\0\')')
    parser.add_argument('-d', '--delete-leak',          nargs='*',                      help='delete leak(s) from database, e.g. "1-3,5,7-9"', metavar='SOURCE_ID')
    parser.add_argument('-dd', '--deduplication',       action='store_true',            help='deduplicate accounts ahead of time (lots of memory usage on large files)')
    parser.add_argument('--drop',                       action='store_true',            help='delete the entire database D:')
    parser.add_argument('--threads',        type=int,   default=default_threads,        help='number of threads for import operations')
    parser.add_argument('--print0',                     action='store_true',            help='delimit search results by null byte instead of colon')
    parser.add_argument('--limit',          type=int,   default=-1,                     help='limit number of results (default: unlimited)')
    parser.add_argument('-u', '--unattended',           action='store_true',            help='auto-detect import fields without user interaction')
    parser.add_argument('-v', '--verbose',              action='store_true',            help='show what is happening')
    parser.add_argument('--debug',                      action='store_true',            help='display detailed debugging info')

    try:

        if len(sys.argv) < 2:
            parser.print_help()
            sys.exit(0)

        logging.getLogger('credshed').setLevel(logging.INFO)

        options = parser.parse_args()

        if options.verbose or options.debug:
            logging.getLogger('credshed').setLevel(logging.DEBUG)
            options.verbose = True

        if options.ingest and not options.unattended:
            logger.listener.start()
            main(options)

        else:
            p = multiprocessing.Process(target=main, args=(options,))
            p.start()
            logger.listener.start()

    except argparse.ArgumentError as e:
        log.error(e)
        log.error('Check your syntax')
        sys.exit(2)

    finally:
        try:
            p.join()
            logger.listener.stop()
        except:
            pass