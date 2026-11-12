#!/usr/bin/env python3

# by TheTechromancer

import re
import logging
import pymongo
from .util import *
from . import logger
from .errors import *
from .source import *
from .account import *
from time import sleep
from . import validation
from . import regions
from .config import config
from datetime import datetime
from multiprocessing import Manager
from . import ingest_parallel


# set up logging
log = logging.getLogger('credshed.db')


source_lock = Manager().Semaphore()


class DB():


    def __init__(self):

        try:
            self.client = self._get_client()
            self.db = self.client[self.db_name]
            self.accounts = self.db.accounts.with_options(
                write_concern=pymongo.write_concern.WriteConcern(
                    w=0,
                    j=False,
                    fsync=False
                ),
            )
        except CredShedError as e:
            raise CredShedDatabaseError('Failed to contact database')            

        # sources
        self.sources = self.db.sources

        # create indexes
        self.sources.create_index([('source_id', pymongo.ASCENDING)], unique=True)
        #self.sources.create_index([('source_id', pymongo.ASCENDING)], background=True)
        #self.accounts.create_index([('u', pymongo.ASCENDING)], sparse=True, background=True)
        #self.accounts.create_index([('e', pymongo.ASCENDING)], sparse=True, background=True)


    def drop(self):
        '''
        Deletes all data from the database
        '''
        log.info('Deleting "sources" collection"')
        self.sources.delete_many({})
        log.info('Deleting "accounts" collection"')
        self.accounts.delete_many({})
        log.info('Done')




    def find_one(self, _id):
        '''
        retrieves one account by id
        '''

        try:
            return Account.from_document(self.accounts.find({'_id': _id}).next())
        except (pymongo.errors.PyMongoError, StopIteration) as e:
            raise CredShedDatabaseError(error_detail(e))



    def search(self, keyword, query_type='email', limit=10000, max_time_ms=None):
        '''
        searches by keyword using regex
        ~ 2 minutes to regex-search non-indexed 100M-entry DB

        max_time_ms bounds the server-side scan so an un-indexed query (e.g. a
        password search on a deployment that hasn't built idx_p) can't pin a
        thread on a full-collection scan — the web API passes a bound; the CLI
        leaves it None (unbounded) for deliberate long scans.
        '''

        query = self._build_query(keyword, query_type)

        for result in self._op(
                self.accounts.find,
                query,
                limit=limit,
                max_time_ms=max_time_ms,
            ):
            try:
                account = Account.from_document(result)
                yield account
            except AccountCreationError as e:
                log.warning(str(e))
                #import traceback
                #log.warning(traceback.format_exc())
                log.warning(result)


    def count(self, keyword, query_type='email'):

        try:

            query = self._build_query(keyword, query_type)
            return self.accounts.count_documents(query)

        except pymongo.errors.PyMongoError as e:
            raise CredShedDatabaseError(error_detail(e))



    def account_count(self):

        try:
            collstats = self.db.command('collstats', 'accounts', scale=1048576)
            num_accounts_in_db = collstats['count']
        except KeyError:
            num_accounts_in_db = 0
        except pymongo.errors.PyMongoError as e:
            raise CredShedDatabaseError(error_detail(e))

        return int(num_accounts_in_db)



    def source_count(self):

        try:
            collstats = self.db.command('collstats', 'sources', scale=1048576)
            num_sources_in_db = collstats['count']
        except KeyError:
            num_sources_in_db = 0
        except pymongo.errors.PyMongoError as e:
            raise CredShedDatabaseError(error_detail(e))

        return int(num_sources_in_db)




    def query_stats(self, keyword, query_type='domain'):

        # {source_id: num_accounts}
        sources = dict()

        query = self._build_query(keyword, query_type)
        for result in self._op(
                self.accounts.find,
                query, {'s': True, '_id': False}
            ):

            try:
                for source_id in result['s']:
                    try:
                        sources[source_id] += 1
                    except KeyError:
                        sources[source_id] = 1

            except KeyError:
                log.error('"s" key missing from account metadata')

        return sources



    def delete_source(self, source_id, **kwargs):
        '''alias used by CredShed.delete_source()'''
        return self.delete_leak(int(source_id), **kwargs)


    def stats(self, accounts=True, sources=True, db=True, regions_limit=12):
        '''
        Human-readable database summary, including the new DFIR regional
        breakdown.  Returned as a string (printed by `--db-stats`).
        '''
        lines = []
        total_accounts = self.account_count()
        total_sources = self.source_count()
        lines.append('=' * 64)
        lines.append(f'  CREDSHED DATABASE: {total_accounts:,} accounts across {total_sources:,} source(s)')
        lines.append(f'  Secondary indexes: {", ".join(self.index_info())}')
        lines.append('=' * 64)

        if sources:
            lines.append('\nSOURCES:')
            for src in self.sources.find({}, {
                    'source_id': 1, 'name': 1, 'total_accounts': 1,
                    'parser_format': 1, 'login_types': 1, 'phone_count': 1,
                    'import_finished': 1}).sort('source_id', 1):
                lt = src.get('login_types', {}) or {}
                flag = '' if src.get('import_finished', True) else '  [IMPORT INCOMPLETE]'
                lines.append(
                    f"  [{src.get('source_id','?'):>4}] {str(src.get('name',''))[:48]:48} "
                    f"{src.get('total_accounts',0):>12,} acct  "
                    f"fmt={src.get('parser_format','?') or '?':7} "
                    f"(e:{lt.get('email',0):,} u:{lt.get('username',0):,} "
                    f"p:{lt.get('phone',0):,}){flag}")

        if db and total_accounts:
            rs = self.region_stats(target='email')
            if rs['regions']:
                lines.append('\nTOP EMAIL-DOMAIN REGIONS (victim geography):')
                for region, count in rs['regions'][:regions_limit]:
                    bar = '#' * int(40 * count / max(1, rs['regions'][0][1]))
                    lines.append(f"  {region:30} {count:>12,}  {bar}")
                lines.append('\nTOP COUNTRIES (by email domain zone):')
                for country, count in rs['countries'][:regions_limit]:
                    lines.append(f"  {country:30} {count:>12,}")
        lines.append('')
        return '\n'.join(lines)


    def _build_query(self, keyword, query_type='email'):


        query_type = validation.validate_query_type(keyword, query_type)

        if query_type == 'email':
            try:
                email, domain = keyword.lower().split('@')[:2]
                email, domain = Account.handle_special_email_cases(email, domain)
                # _id begins with reversed domain
                domain_chunk = re.escape(domain[::-1])
                email_hash = base64.b64encode(hashlib.sha1(email.encode()).digest()[:6]).decode()
                # email_hash = decode(base64.b64encode(hashlib.sha256(encode(email)).digest()[:6]))
                query_str = domain_chunk + '\\|' +  re.escape(email_hash)

                query_regex = rf'^{query_str}.*'
                query = {'_id': {'$regex': query_regex}}

            except ValueError:
                raise CredShedError('Invalid email')

        elif query_type == 'domain':
            domain = keyword.lower()
            domain = re.escape(domain[::-1])

            if domain.endswith('.'):
                # if query is like ".com"
                query_regex = rf'^{domain}[\w.]*\|'
            else:
                # or if query is like "example.com"
                query_regex = rf'^{domain}[\.\|]'

            query = {'_id': {'$regex': query_regex}}

        elif query_type == 'tld':
            # domain-zone search on the EMAIL domain (victim geography), e.g. ".ru"
            # _id starts with the reversed email domain, so the zone is a reversed prefix
            zone = keyword.strip().lower().lstrip('.')
            rev = re.escape(zone[::-1])
            query = {'_id': {'$regex': rf'^{rev}\.'}}

        elif query_type == 'username':
            # exact match (index-friendly).  A purely numeric login may have been
            # routed to the phone field, so match either for numeric pivots.
            if keyword.isdigit():
                query = {'$or': [{'u': keyword}, {'t': keyword}]}
            else:
                query = {'u': keyword}

        elif query_type == 'password':
            # reverse search: "who used this password?"
            query = {'p': keyword}

        elif query_type == 'hash':
            # reverse search by hash value (e.g. look a hash up against potfile data)
            query = {'h': keyword}

        elif query_type == 'phone':
            norm = validation.normalize_phone(keyword)
            if not norm:
                raise CredShedError(f'Invalid phone number: "{keyword}"')
            # a bare numeric login may sit in the username field; match either
            query = {'$or': [{'t': norm}, {'u': norm}]}

        elif query_type == 'service':
            kw = keyword.strip().lower()
            if kw.startswith('.'):
                # service-zone query, e.g. "-q service .ru"
                rev = re.escape(kw.lstrip('.')[::-1])
                query = {'v': {'$regex': rf'^{rev}\.'}}
            else:
                # service host: the host itself OR any of its subdomains.
                # Split into an exact match + an anchored "host." prefix regex so
                # BOTH arms get index bounds (a single ^...(?:\.|$) regex does not).
                host = validation.extract_host(kw)
                rev = host[::-1]
                query = {'$or': [
                    {'v': rev},
                    {'v': {'$regex': rf'^{re.escape(rev)}\.'}},
                ]}

        else:
            raise CredShedError(f'Invalid query type: {query_type}')

        log.debug(f'Raw mongo query: {query}')
        return query


    # DFIR enhancement: index management.  Bulk-load with no secondary indexes
    # (fast writes), then build only the dimensions a given engagement needs.
    SECONDARY_INDEX_FIELDS = {
        'u': 'username', 'p': 'password', 't': 'phone', 'v': 'service', 'h': 'hash',
    }

    def build_indexes(self, fields=None):
        '''
        Build secondary indexes for the given doc-field keys (default: all of
        u/p/t/v).  Returns the list of fields indexed.  Sparse, because most
        docs only populate a subset of these.
        '''
        if fields is None:
            fields = list(self.SECONDARY_INDEX_FIELDS)
        built = []
        for f in fields:
            name = f'idx_{f}'
            log.info(f'Building index "{name}" on accounts.{f} '
                     f'({self.SECONDARY_INDEX_FIELDS.get(f, f)}) ...')
            self._op(self.accounts.create_index, [(f, pymongo.ASCENDING)],
                     name=name, sparse=True)
            built.append(f)
        log.info(f'Built {len(built)} index(es): {built}')
        return built

    def drop_secondary_indexes(self):
        dropped = []
        for ix in self.accounts.list_indexes():
            if ix['name'] != '_id_':
                self.accounts.drop_index(ix['name'])
                dropped.append(ix['name'])
        return dropped

    def index_info(self):
        try:
            return [ix['name'] for ix in self.accounts.list_indexes()]
        except pymongo.errors.PyMongoError:
            return ['_id_']


    @staticmethod
    def _escape_keys(d):
        # Mongo field names can't contain '.' or NUL, or start with '$'.
        # Use a reversible marker-escape ('~') so the round-trip is lossless and
        # collision-free even for dirty service hosts (keys double as stat labels).
        def esc(k):
            k = validation.control_chars_re.sub('', str(k))
            return k.replace('~', '~t').replace('.', '~d').replace('$', '~s')
        return {esc(k): v for k, v in d.items() if k}

    @staticmethod
    def _unescape_keys(d):
        def unesc(k):
            # reverse order: decode '.' and '$' first, then the '~' marker last
            return k.replace('~d', '.').replace('~s', '$').replace('~t', '~')
        return {unesc(k): v for k, v in (d or {}).items()}


    def tld_stats(self, target='email', limit=None):
        '''
        DB-wide domain-zone histogram, assembled from the per-source histograms
        stored in the `sources` collection (no account scan required).

        target: 'email'   -> victim geography (email-domain zones)
                'service' -> breached-service zones
        Returns a list of (tld, count) sorted descending.
        '''
        field = 'service_tld_hist' if target == 'service' else 'email_tld_hist'
        agg = {}
        for src in self.sources.find({}, {field: 1}):
            for k, v in self._unescape_keys(src.get(field, {})).items():
                agg[k] = agg.get(k, 0) + int(v)
        items = sorted(agg.items(), key=lambda x: x[1], reverse=True)
        return items[:limit] if limit else items

    def global_summary(self, top_n=15, zones_top=60):
        '''
        One fast, account-scan-free snapshot of the whole database, assembled
        purely from the per-source histograms in the `sources` collection.
        Powers the statistics dashboard.
        '''
        totals = {'accounts': 0, 'sources': 0, 'email': 0, 'username': 0,
                  'phone': 0, 'with_password': 0, 'with_hash': 0, 'with_service': 0,
                  'filesize': 0}
        domains, services, email_tld, service_tld = {}, {}, {}, {}
        pw_words, formats = {}, {}
        passwords, pw_len = {}, {}
        sources = []

        for s in self.sources.find({}):
            totals['sources'] += 1
            n = int(s.get('total_accounts', 0) or 0)
            totals['accounts'] += n
            lt = s.get('login_types', {}) or {}
            totals['email'] += int(lt.get('email', 0) or 0)
            totals['username'] += int(lt.get('username', 0) or 0)
            totals['phone'] += int(s.get('phone_count', 0) or 0)
            totals['with_password'] += int(s.get('with_password', 0) or 0)
            totals['with_hash'] += int(s.get('with_hash', 0) or 0)
            totals['with_service'] += int(s.get('with_service', 0) or 0)
            totals['filesize'] += int(s.get('filesize', 0) or 0)
            fmt = s.get('parser_format') or 'unknown'
            formats[fmt] = formats.get(fmt, 0) + n

            def merge(dst, field):
                for k, v in self._unescape_keys(s.get(field, {})).items():
                    dst[k] = dst.get(k, 0) + int(v)
            merge(domains, 'top_domains')
            merge(services, 'top_services')
            merge(email_tld, 'email_tld_hist')
            merge(service_tld, 'service_tld_hist')
            for k, v in (s.get('top_password_basewords', {}) or {}).items():
                pw_words[k] = pw_words.get(k, 0) + int(v)
            for k, v in self._unescape_keys(s.get('top_passwords', {})).items():
                passwords[k] = passwords.get(k, 0) + int(v)
            for k, v in (s.get('password_length_hist', {}) or {}).items():
                try:
                    pw_len[int(k)] = pw_len.get(int(k), 0) + int(v)
                except (ValueError, TypeError):
                    pass

            sources.append({
                'source_id': s.get('source_id'),
                'name': str(s.get('name', ''))[-60:],
                'total_accounts': n,
                'parser_format': fmt,
                'login_types': {'email': int(lt.get('email', 0) or 0),
                                'username': int(lt.get('username', 0) or 0),
                                'phone': int(s.get('phone_count', 0) or 0)},
                'with_password': int(s.get('with_password', 0) or 0),
                'with_service': int(s.get('with_service', 0) or 0),
                'import_finished': s.get('import_finished', True),
            })

        def top(d):
            return sorted(d.items(), key=lambda x: x[1], reverse=True)[:top_n]

        return {
            'totals': totals,
            'indexes': self.index_info(),
            'formats': sorted(formats.items(), key=lambda x: x[1], reverse=True),
            'sources': sorted(sources, key=lambda x: x.get('source_id') or 0),
            'top_domains': top(domains),
            'top_services': top(services),
            'top_password_basewords': top(pw_words),
            'top_passwords': top(passwords),
            'password_lengths': sorted(pw_len.items()),
            'regions_email': self._regions_from_hist(email_tld, zones_top),
            'regions_service': self._regions_from_hist(service_tld, zones_top),
        }

    def _regions_from_hist(self, hist, zones_top=60):
        '''roll a {tld: count} histogram up into zones/countries/regions'''
        countries, region_rollup = {}, {}
        for tld, count in hist.items():
            country, region = regions.region_of(tld)
            label = country if country else (f'.{tld}' if tld else 'unknown')
            countries[label] = countries.get(label, 0) + count
            region_rollup[region] = region_rollup.get(region, 0) + count
        srt = lambda d: sorted(d.items(), key=lambda x: x[1], reverse=True)
        return {
            'zones': srt(hist)[:zones_top],
            'countries': srt(countries),
            'regions': srt(region_rollup),
        }

    def region_stats(self, target='email'):
        '''
        Roll the zone histogram up into (country, region) buckets for a
        human-readable regional breakdown.  Returns dict with 'zones',
        'countries', 'regions' (each a sorted list of (name, count)).
        '''
        zones = self.tld_stats(target=target)
        countries = {}
        region_rollup = {}
        for tld, count in zones:
            country, region = regions.region_of(tld)
            label = country if country else (f'.{tld}' if tld else 'unknown')
            countries[label] = countries.get(label, 0) + count
            region_rollup[region] = region_rollup.get(region, 0) + count
        return {
            'zones': zones,
            'countries': sorted(countries.items(), key=lambda x: x[1], reverse=True),
            'regions': sorted(region_rollup.items(), key=lambda x: x[1], reverse=True),
        }

    def source_detail(self, source_id, top_n=2000, zones_top=3000):
        '''
        Detailed statistics for ONE ingested source (dataset), assembled from the
        per-source histograms stored at ingest time — mirrors global_summary but
        scoped to a single source_id.  Powers the dashboard's per-dataset view.
        '''
        s = self.sources.find_one({'source_id': int(source_id)})
        if not s:
            raise CredShedError(f'No source with id {source_id}')

        unesc = self._unescape_keys
        domains     = unesc(s.get('top_domains', {}))
        services    = unesc(s.get('top_services', {}))
        email_tld   = unesc(s.get('email_tld_hist', {}))
        service_tld = unesc(s.get('service_tld_hist', {}))
        pw   = s.get('top_password_basewords', {}) or {}
        misc = s.get('top_misc_basewords', {}) or {}
        pwd  = unesc(s.get('top_passwords', {}))
        plen = s.get('password_length_hist', {}) or {}
        lt   = s.get('login_types', {}) or {}

        def top(d):
            return sorted(d.items(), key=lambda x: x[1], reverse=True)[:top_n]

        return {
            'source_id': s.get('source_id'),
            'name': str(s.get('name', '')),
            'files': [str(f) for f in (s.get('files') or [])],
            'filesize': int(s.get('filesize', 0) or 0),
            'parser_format': s.get('parser_format') or 'unknown',
            'description': str(s.get('description', '') or ''),
            'created_date': str(s.get('created_date', '') or ''),
            'modified_date': str(s.get('modified_date', '') or ''),
            'import_finished': bool(s.get('import_finished', True)),
            'totals': {
                'accounts': int(s.get('total_accounts', 0) or 0),
                'email': int(lt.get('email', 0) or 0),
                'username': int(lt.get('username', 0) or 0),
                'phone': int(s.get('phone_count', 0) or 0),
                'with_password': int(s.get('with_password', 0) or 0),
                'with_hash': int(s.get('with_hash', 0) or 0),
                'with_service': int(s.get('with_service', 0) or 0),
            },
            'top_domains': top(domains),
            'top_services': top(services),
            'top_password_basewords': top(pw),
            'top_misc_basewords': top(misc),
            'top_passwords': top(pwd),
            'password_lengths': sorted(((int(k), int(v)) for k, v in plen.items()
                                        if str(k).isdigit()), key=lambda x: x[0]),
            'regions_email': self._regions_from_hist(email_tld, zones_top),
            'regions_service': self._regions_from_hist(service_tld, zones_top),
        }



    def _domains_in_zone(self, zone, top_n=200):
        '''
        Top email domains that belong to a TLD zone, rolled up from the per-source
        top_domains histograms (no account scan).  Fast + exact for the heavy
        hitters that the stored histograms keep.
        '''
        agg = {}
        for s in self.sources.find({}, {'top_domains': 1}):
            for d, c in self._unescape_keys(s.get('top_domains', {})).items():
                if validation.tld_of(d) == zone:
                    agg[d] = agg.get(d, 0) + int(c)
        return sorted(agg.items(), key=lambda x: x[1], reverse=True)[:top_n]

    def tld_detail(self, zone, target='email', top_n=200, sample=30, max_ms=10000):
        '''
        DFIR drill-down for ONE domain zone (e.g. ".kz").  Returns the account
        total, the domains under the zone, and the top passwords / services /
        usernames used by accounts in it, plus a handful of real sample records —
        everything an investigator needs to understand a zone's threat landscape.

        target='email'   -> victim geography: accounts whose EMAIL domain is in
                            the zone (matched on the reversed-domain _id prefix,
                            so the _id index bounds the scan).
        target='service' -> accounts whose BREACHED SERVICE is in the zone
                            (matched on the reversed service field 'v').

        Group stages run with maxTimeMS so a giant generic zone (.com) returns a
        bounded, best-effort result instead of hanging; ccTLDs are fast.
        '''
        zone = str(zone).strip().lower().lstrip('.')
        if not zone or not re.match(r'^[a-z0-9][a-z0-9.\-]{0,23}$', zone):
            raise CredShedError(f'Invalid TLD zone: {zone!r}')
        rev = re.escape(zone[::-1])
        if target == 'service':
            match = {'v': {'$regex': rf'^{rev}\.'}}
        else:
            match = {'_id': {'$regex': rf'^{rev}\.'}}
        coll = self.accounts

        # One pass over the zone-matched docs computes the count AND every top-N
        # list via $facet, instead of 4 separate collection scans — one shared
        # maxTimeMS budget bounds the whole thing so a giant zone (.com) degrades
        # gracefully (empty/None) rather than tying up the DB.
        def grp(field):
            return [{'$match': {field: {'$type': 'string'}}},
                    {'$group': {'_id': f'${field}', 'c': {'$sum': 1}}},
                    {'$sort': {'c': -1}}, {'$limit': int(top_n)}]
        def has(f):   # 1 when field f is present on the doc, else 0
            return {'$cond': [{'$ne': [{'$type': f'${f}'}, 'missing']}, 1, 0]}
        facets = {
            'count': [{'$count': 'n'}],
            'p': grp('p'), 'u': grp('u'),
            # coverage + login-type split, same single pass (investigator context:
            # "what share of this zone's accounts expose a plaintext password / a
            # breached service / a hash", and how the accounts identify their owner)
            'cov': [{'$group': {'_id': None,
                                'with_password': {'$sum': has('p')},
                                'with_service': {'$sum': has('v')},
                                'with_hash': {'$sum': has('h')},
                                'email': {'$sum': has('e')},
                                'username': {'$sum': has('u')},
                                'phone': {'$sum': has('t')}}}],
        }
        if target != 'service':
            facets['v'] = grp('v')
        total, passwords, usernames, services = None, [], [], []
        coverage, login_types = {}, {}
        try:
            res = next(coll.aggregate([{'$match': match}, {'$facet': facets}],
                                      maxTimeMS=max_ms, allowDiskUse=True), {})

            def unpack(key, reverse=False):
                out = []
                for d in res.get(key, []):
                    k = d.get('_id')
                    if k:
                        out.append(((k[::-1] if reverse else k), int(d['c'])))
                return out
            cnt = res.get('count') or []
            total = int(cnt[0]['n']) if cnt else 0
            passwords = unpack('p')
            usernames = unpack('u')
            services = unpack('v', reverse=True) if target != 'service' else []
            cov = (res.get('cov') or [{}])[0]
            coverage = {k: int(cov.get(k, 0) or 0)
                        for k in ('with_password', 'with_service', 'with_hash')}
            login_types = {k: int(cov.get(k, 0) or 0) for k in ('email', 'username', 'phone')}
        except pymongo.errors.PyMongoError as e:
            log.warning(f'tld_detail aggregation for .{zone}: {e}')

        domains = self._domains_in_zone(zone, top_n) if target == 'email' else []

        samples = []
        try:
            for doc in coll.find(match, limit=int(sample), max_time_ms=max_ms):
                try:
                    samples.append(Account.from_document(doc).json)
                except Exception:
                    continue
        except pymongo.errors.PyMongoError:
            pass

        return {
            'zone': zone, 'target': target, 'total_accounts': total,
            'coverage': coverage, 'login_types': login_types,
            'top_domains': domains, 'top_passwords': passwords,
            'top_services': services, 'top_usernames': usernames,
            'sample': samples,
        }

    def search_records(self, keyword, query_type='auto', limit=100, max_time_ms=10000):
        '''
        Thin wrapper used by the data-search API: validate the query type, run the
        indexed search, and return account records as plain dicts (human JSON).
        Read-only; honours the same per-field indexes the CLI search uses.

        The scan is time-bounded (max_time_ms) so an un-indexed field search can
        never pin a web worker on a full 19.7M-doc scan; on timeout it returns the
        partial results gathered so far with truncated=True.
        '''
        qt = validation.validate_query_type(keyword, query_type)
        out = []
        truncated = False
        try:
            for doc in self.search(str(keyword), query_type=qt, limit=int(limit),
                                   max_time_ms=max_time_ms):
                try:
                    out.append(doc.json)
                except Exception:
                    continue
        except pymongo.errors.ExecutionTimeout:
            truncated = True
        return {'query': str(keyword), 'type': qt, 'count': len(out),
                'results': out, 'truncated': truncated}


    def add_accounts(self, source, force=False, batch_size=5000, workers=1,
                     write_threads=2, chunk_factor=8):
        '''
        Given a Source object, import it plus all of its accounts.

        Write path: insert_many(unordered) at w=1 — roughly 3x faster than per-
        document upserts (no per-doc _id index probe) and acknowledged, so write
        errors surface instead of being silently dropped.  Accounts that collide on
        _id (already present, from this or another source) come back as duplicate-
        key errors; we merge this source into their `s` array afterwards, so cross-
        file provenance is preserved exactly as the old $setOnInsert/$addToSet did
        (first write wins on the body; every source that saw the account is recorded).

        DFIR enhancement: with workers > 1, a single plain-text file is split into
        newline-aligned byte ranges and ingested by that many parallel processes
        (one Mongo connection each), turning a one-core ~30 k/s parse into an
        N-core, N-write-stream load.  Non-splittable inputs (multi-line 'blocks',
        compressed, tiny) transparently fall back to this single-threaded path.

        https://www.percona.com/blog/2020/05/05/tuning-mongodb-for-bulk-loads/
        '''

        # ---- fast path: parallel single-file ingest -------------------------
        if workers and workers > 1:
            if getattr(source, 'parser', None) is None:
                source.parse(unattended=True)
            presniff = source.parser.sniff_params()
            ok, why = ingest_parallel.can_parallelize(source.file, presniff)
            if ok and source.file.size > (4 * batch_size):
                return self._add_accounts_parallel(
                    source, workers, presniff, force=force, batch_size=batch_size,
                    write_threads=write_threads, chunk_factor=chunk_factor)
            log.info(f'Parallel ingest not applicable ({why or "file too small"}); '
                     f'using single-threaded path')

        try:
            client = self._get_client()
            db = client[self.db_name]
            # w=1: acknowledged, so insert_many reports duplicates (needed for the
            # provenance merge) and real write errors aren't swallowed.
            accounts_collection = db.accounts.with_options(
                write_concern=pymongo.write_concern.WriteConcern(w=1),
            )
        except CredShedError as e:
            raise CredShedDatabaseError(f'Failed to contact database: {e}')

        # check to make sure there's at least one account
        try:
            first_account = next(source.__iter__())
        except StopIteration:
            log.warning(f'No accounts found in {source.file}')
            return

        # create the source and get the source ID
        try:
            new_source = self.add_source(source, import_finished=False, force=force, client=client)
        except AlreadyInProgressError:
            return

        if not (new_source['import_finished'] == False or force):
            log.warning(f'Skipping file "{source.file}", already in database')
            self.add_source(source, import_finished=True, force=force, client=client)
            return

        account_stream = self.account_stream(
            source,
            first_account=first_account,
            batch_size=batch_size
        )

        try:
            total_size = source.file.size
        except Exception:
            total_size = 0
        import_start = datetime.now()
        last_log = import_start

        source.unique_accounts = 0
        for batch in account_stream:
            source.unique_accounts += self._write_batch(accounts_collection, batch, source.id)
            now = datetime.now()
            if (now - last_log).total_seconds() >= 2:
                self._log_progress(source, import_start, total_size)
                last_log = now

        self._log_progress(source, import_start, total_size, final=True)

        # update counters, stats, etc.
        self.add_source(source, import_finished=True, force=force, client=client)


    def _add_accounts_parallel(self, source, workers, presniff, force=False, batch_size=5000,
                               write_threads=2, chunk_factor=8):
        '''
        Parallel single-file ingest (see add_accounts / lib.ingest_parallel).
        Assigns the source id, forks `workers` byte-range workers, merges their
        partial per-source histograms back, then finalizes the source doc.
        '''
        # reserve the source id + write the placeholder source doc
        try:
            new_source = self.add_source(source, import_finished=False, force=force)
        except AlreadyInProgressError:
            return
        if not (new_source['import_finished'] == False or force):
            log.warning(f'Skipping file "{source.file}", already in database')
            self.add_source(source, import_finished=True, force=force)
            return

        encoding = source.file.encoding
        total_size = source.file.size
        import_start = datetime.now()
        state = {'last': import_start}

        def progress_cb(done):
            now = datetime.now()
            if done < total_size and (now - state['last']).total_seconds() < 2:
                return
            state['last'] = now
            elapsed = max(1e-6, (now - import_start).total_seconds())
            pct = (done / total_size * 100) if total_size else 0.0
            bps = done / elapsed
            eta_s = max(0.0, (total_size - done) / bps) if bps > 0 else 0.0
            eta = f'{int(eta_s // 3600):02d}:{int((eta_s % 3600) // 60):02d}:{int(eta_s % 60):02d}'
            log.info(f'{source.file.name}: {pct:5.1f}% | '
                     f'{done // 1000000:,}/{total_size // 1000000:,}MB | '
                     f'{workers} workers | ETA {eta}')

        log.info(f'Parallel ingest: "{source.file.name}" format={presniff["format"]} '
                 f'across {workers} workers')
        partials, all_ok = ingest_parallel.run_parallel_ingest(
            source, workers, presniff, encoding,
            batch_size=batch_size, progress_cb=progress_cb,
            write_threads=write_threads, chunk_factor=chunk_factor)

        # fold partial histograms back so the stored stats match a serial parse
        ingest_parallel.merge_stats_into_source(source, partials)
        source.parser = ingest_parallel._FormatHolder(presniff['format'])

        elapsed = max(1e-6, (datetime.now() - import_start).total_seconds())
        log.info(f'{source.file.name}: done | {source.total_accounts:,} rows | '
                 f'{source.total_accounts / elapsed:,.0f} accounts/s ingest')

        # finalize: write the merged histograms.  Only mark the import finished if
        # EVERY worker completed cleanly — a dead/failed worker means a byte range
        # was not fully written, so we leave import_finished=False (shown as
        # "[IMPORT INCOMPLETE]") rather than silently recording a partial file as
        # complete; re-running with --force retries it.
        if not all_ok:
            log.error(f'{source.file.name}: PARALLEL IMPORT INCOMPLETE — some rows '
                      f'may be missing; left unfinished (re-run with --force to retry)')
        self.add_source(source, import_finished=all_ok, force=force)


    def _write_batch(self, coll, docs, source_id):
        '''
        Insert a batch of account documents (unordered).  _id collisions mean the
        account already exists (same or another source) — merge this source into
        their `s` array so provenance is preserved.  Retries transient errors.
        Returns the number of NEW (actually inserted) documents (for unique_accounts).
        '''
        if not docs:
            return 0
        while True:
            try:
                coll.insert_many(docs, ordered=False)
                return len(docs)
            except pymongo.errors.BulkWriteError as bwe:
                errs = bwe.details.get('writeErrors', [])
                dup_ids, other = [], 0
                for e in errs:
                    if e.get('code') == 11000:          # duplicate key
                        _id = (e.get('op') or {}).get('_id')
                        if _id is not None:
                            dup_ids.append(_id)
                    else:
                        other += 1
                if other:
                    log.warning(f'{other} non-duplicate write error(s) for source {source_id}')
                if dup_ids:
                    self._op(
                        coll.bulk_write,
                        [pymongo.UpdateOne({'_id': _id}, {'$addToSet': {'s': source_id}}) for _id in dup_ids],
                        ordered=False
                    )
                return max(0, len(docs) - len(errs))
            except pymongo.errors.PyMongoError as e:
                log.error('Encountered error in insert_many; retrying in 30 seconds...')
                log.error(error_detail(e))
                sleep(30)
                continue


    @staticmethod
    def _log_progress(source, import_start, total_size, final=False):
        '''Readable progress: % of file read, rows so far, throughput, ETA.'''
        now = datetime.now()
        elapsed = max(1e-6, (now - import_start).total_seconds())
        rows = source.total_accounts
        if final:
            done, pct, eta_s = total_size, 100.0, 0.0
        else:
            try:
                done = source.file.bytes_read
            except Exception:
                done = 0
            pct = (done / total_size * 100) if total_size else 0.0
            bps = done / elapsed
            eta_s = max(0.0, (total_size - done) / bps) if (bps > 0 and total_size) else 0.0
        eta = f'{int(eta_s // 3600):02d}:{int((eta_s % 3600) // 60):02d}:{int(eta_s % 60):02d}'
        rpm = rows / elapsed * 60
        try:
            name = source.file.name
        except Exception:
            name = str(source.file)
        log.info(
            f'{name}: {("done " if final else "")}{pct:5.1f}% | {rows:,} rows | '
            f'{done // 1000000:,}/{total_size // 1000000:,}MB | '
            f'{rpm / 1000:,.0f}k rows/min | ETA {eta}'
        )



    def _op(self, func, *args, **kwargs):
        '''
        automatically retries, handling pymongo errors
        '''

        while 1:
            try:
                return func(*args, **kwargs)

            except pymongo.errors.DuplicateKeyError:
                raise

            except pymongo.errors.PyMongoError as e:
                log.error('Encountered error in DB._op()')
                log.error(error_detail(e))
                log.error('Retrying in 30 seconds...')
                sleep(30)
                continue



    def account_stream(self, source, first_account=None, batch_size=5000):

        batch = []

        if first_account is not None:
            batch.append(self._account_doc(first_account, source.id))

        for account in source:
            batch.append(self._account_doc(account, source.id))

            if len(batch) >= batch_size:
                yield batch
                batch = []

        if batch:
            yield batch



    @staticmethod
    def _account_doc(account, source_id):
        '''
        Build the full account document for insert_many, tagged with its source.
        First write wins on the body; duplicate _ids get this source merged into
        `s` afterwards (see _write_batch), so provenance matches the old upsert.
        '''
        doc = account.document        # dict incl _id + populated fields
        doc['s'] = [source_id]
        return doc



    def delete_leak(self, source_id, batch_size=5000):

        source = self.get_source(source_id)
        accounts_deleted = 0
        to_delete = []

        hashtype = getattr(source, 'hashtype', None)
        log.info('\nDeleting leak "{}{}"'.format(source.name, ':{}'.format(hashtype) if hashtype else ''))

        # make the source-membership scans below use an index instead of COLLSCAN
        try:
            self.accounts.create_index([('s', pymongo.ASCENDING)], name='idx_s', sparse=True)
        except pymongo.errors.PyMongoError:
            pass

        try:

            # delete accounts that belong ONLY to this source
            for result in self.accounts.find({'s': [source_id]}, {'_id': 1}):
                to_delete.append(pymongo.DeleteOne(result))
                if len(to_delete) % batch_size == 0:
                    accounts_deleted += self.accounts.bulk_write(to_delete, ordered=False).deleted_count
                    to_delete.clear()
                    errprint('\rDeleted {:,} accounts'.format(accounts_deleted), end='')

            if to_delete:
                accounts_deleted += self.accounts.bulk_write(to_delete, ordered=False).deleted_count

            # for accounts shared with other sources, just pull this source ID
            self.accounts.update_many({'s': source_id}, {'$pull': {'s': source_id}})

            errprint('\r[+] Deleted {:,} accounts'.format(accounts_deleted), end='')

            self.sources.delete_many({'_id': source_id})


        except TypeError as e:
            log.error(str(e))
            log.error('[!] Can\'t find source "{}:{}"'.format(source.name, getattr(source, 'hashtype', None)))

        errprint('')
        log.info('{:,} accounts deleted'.format(accounts_deleted))

        return accounts_deleted


    def add_source(self, source, import_finished=False, force=False, client=None, already_in_progress=False):
        '''
        Inserts source details such as name, description, hash, etc.
        Returns new or existing Leak ID
        DOES NOT import accounts (use the Injestor)

        The reason we need _id AND hash is because _id is used in accounts_metadata
        to keep track of account/source associations.  the hash takes up too much space

        Meant to be called twice:
            - Once before a source is imported in order to get the Source ID
            - Again after a source is imported to update file list and account counters
        '''

        if client is None:
            client = self.client

        db = client[self.db_name]
        sources = db.sources

        # perform costly operations outside of file lock
        source.hash
        source.file.size

        source.id = self.highest_source_id(client=client) + 1

        source_doc = {
            '_id': source.hash,
            'name': str(source.file),
            'source_id': source.id,
            'filename': str(source.file),
            'files': [str(source.file)],
            'filesize': source.file.size,
            'description': source.description,
            'top_domains': self._escape_keys(source.top_domains(1000)),
            'top_misc_basewords': source.top_misc_basewords(200),
            'top_password_basewords': source.top_password_basewords(1000),
            'top_passwords': self._escape_keys(source.top_passwords(1000)),
            'password_length_hist': {str(k): v for k, v in source.password_lengths.items()},
            # DFIR enhancement: per-source histograms powering fast regional / service stats
            'top_services': self._escape_keys(source.top_services(1000)),
            'email_tld_hist': self._escape_keys(source.email_tld_histogram()),
            'service_tld_hist': self._escape_keys(source.service_tld_histogram()),
            'login_types': source.login_types,
            'phone_count': source.phone_count,
            'with_password': source.with_password,
            'with_hash': source.with_hash,
            'with_service': source.with_service,
            'parser_format': getattr(source.parser, 'format', None),
            'created_date': datetime.now(),
            'modified_date': datetime.now(),
            'total_accounts': source.total_accounts,
            'import_finished': import_finished
        }

        # make sure it doesn't already exist
        existing_source = self._op(
            sources.find_one,
            {'_id': source.hash}
        )

        if existing_source is None:
            log.debug(f'{source.file} not yet in DB')
            
            while 1:
                # create the source
                try:
                    self._op(
                        sources.insert_one,
                        source_doc
                    )
                    log.debug(f'new_source: {str(source_doc)}')
                    return source_doc

                except pymongo.errors.DuplicateKeyError as e:
                    # this happens because we sort by size
                    if '_id_ dup key' in e.details['errmsg']:
                        sleep(1)
                        return self.add_source(source, import_finished, force, client, already_in_progress=True)
                    else:
                        source.id += 1
                        source_doc['source_id'] = source.id
                        continue

                except pymongo.errors.PyMongoError as e:
                    raise CredShedDatabaseError(error_detail(e))


        log.debug(f'Matching hash already exists for {source.file}, updating...')
        log.debug(f'existing_source: {str(existing_source)}')

        self._op(
            sources.update_one,
            {'_id': source.hash}, {
                '$addToSet': {
                    'files': str(source.name)
                },
                '$set': {
                    'modified_date': datetime.now(),
                    'import_finished': (import_finished or existing_source['import_finished'])
                },
                '$max': {
                    'total_accounts': source.total_accounts,
                }
            }
        )

        if already_in_progress and not force:
            raise AlreadyInProgressError(f'Import for {source.file} is already in progress')

        # only update these if import finished successfully
        # this prevents messing up existing data when cancelling an import operation
        if import_finished and (existing_source['import_finished'] == False or force):

            self._op(
                sources.update_one,
                {'_id': source.hash}, {
                    '$set': {
                        'top_domains': self._escape_keys(source.top_domains(1000)),
                        'top_misc_basewords': source.top_misc_basewords(200),
                        'top_password_basewords': source.top_password_basewords(1000),
            'top_passwords': self._escape_keys(source.top_passwords(1000)),
            'password_length_hist': {str(k): v for k, v in source.password_lengths.items()},
                        'top_services': self._escape_keys(source.top_services(1000)),
                        'email_tld_hist': self._escape_keys(source.email_tld_histogram()),
                        'service_tld_hist': self._escape_keys(source.service_tld_histogram()),
                        'login_types': source.login_types,
                        'phone_count': source.phone_count,
                        'with_password': source.with_password,
                        'with_hash': source.with_hash,
                        'with_service': source.with_service,
                        'parser_format': getattr(source.parser, 'format', None),
                        'total_accounts': source.total_accounts,
                        'import_finished': True
                    }
                }
            )

        # refresh data
        refreshed_source = self._op(
            sources.find_one,
            {'_id': source.hash}
        )

        if refreshed_source is None:
            # if this happens, the source just got deleted
            return existing_source
        else:
            return refreshed_source


    def highest_source_id(self, client=None):
        '''
        returns source with highest ID
        or 1 if there are no leaks loaded
        '''

        if client is None:
            client = self.client

        # get the highest source._id
        try:
            id_counter = next(self._op(
                self.sources.find,
                {},
                {'source_id': 1},
                sort=[('source_id', -1)],
                limit=1)
            )['source_id']
        except StopIteration:
            id_counter = 1

        return max(1, id_counter)


    def get_source(self, source_id):

        try:
            doc = self.sources.find_one({'source_id': int(source_id)})
            if doc:
                return Source.from_doc(doc)
            else:
                raise CredShedError(f'No source found with ID "{source_id}"')

        except pymongo.errors.PyMongoError as e:
            raise CredShedDatabaseError(error_detail(e))



    def _get_client(self, bulk=True):

        try:

            try:
                main_server = config['MONGO']['server']
                main_port = int(config['MONGO']['port'])
                self.db_name = config['MONGO']['db']
                mongo_user = config['MONGO']['user']
                mongo_pass = config['MONGO']['pass']
            except KeyError as e:
                raise CredShedConfigError(str(e))

            return pymongo.MongoClient(
                main_server,
                main_port,
                username=mongo_user,
                password=mongo_pass
            )

        except pymongo.errors.PyMongoError as e:
            raise CredShedDatabaseError(error_detail(e))



    def close(self):

        try:
            self.client.close()
        except AttributeError:
            pass


    def __enter__(self):

        return self


    def __exit__(self, exception_type, exception_value, traceback):

        self.close()