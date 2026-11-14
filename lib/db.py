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


def _require_contains(kw):
    '''A "contains" (substring) term scans a whole secondary index; require a few
    chars so a 1-2 char term (or an empty one) can't drag a 34M-key scan to the time
    limit, and so an empty-normalising term can't become a match-all {"$regex": ""}.'''
    if not kw:
        raise CredShedError('Empty search term')
    if len(kw) < 3:
        raise CredShedError('A "contains" search needs at least 3 characters')


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
        # small key/value collection for precomputed rollups (e.g. the global
        # dashboard summary) so they survive restarts and are shared by all workers
        self.meta = self.db.meta

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



    def search(self, keyword, query_type='email', limit=10000, max_time_ms=None, mode='exact'):
        '''
        searches by keyword using regex
        ~ 2 minutes to regex-search non-indexed 100M-entry DB

        max_time_ms bounds the server-side scan so an un-indexed query (e.g. a
        password search on a deployment that hasn't built idx_p) can't pin a
        thread on a full-collection scan — the web API passes a bound; the CLI
        leaves it None (unbounded) for deliberate long scans.
        '''

        query = self._build_query(keyword, query_type, mode=mode)

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


    def _build_query(self, keyword, query_type='email', mode='exact'):
        # mode='contains' turns the free-text field types (username/password/misc) into a
        # case-insensitive substring match — the "wildcard/partial" search.  The other
        # types keep their own semantics (email/domain prefixes, service subdomains, …).

        query_type = validation.validate_query_type(keyword, query_type)
        contains = (mode == 'contains')

        if query_type == 'email':
            try:
                # normalise the term exactly as ingest does (lowercase, NFC, strip
                # invalid chars) so a search matches the stored, cleaned email
                email, domain = validation.clean_email(keyword).split('@')[:2]
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
            kw = keyword.strip().lower()
            if kw.startswith('.'):
                # ".kz" is a domain-ZONE query (same as tld): emit the tight reversed-
                # zone prefix ^<rev>\. — a bounded _id-index scan — NOT <rev>[^|]*\|,
                # which the planner ran as an unbounded scan to the time limit.  It is
                # Unicode-safe (no \w) so IDN zones and hyphenated subdomains still match.
                zone = kw.lstrip('.')
                if not zone:
                    raise CredShedError('Invalid domain zone (empty)')
                rev = re.escape(zone[::-1])
                query = {'_id': {'$regex': rf'^{rev}\.'}}
            else:
                # "example.com" -> the domain itself OR any subdomain of it
                domain = re.escape(kw[::-1])
                query = {'_id': {'$regex': rf'^{domain}[\.\|]'}}

        elif query_type == 'tld':
            # domain-zone search on the EMAIL domain (victim geography), e.g. ".ru"
            # _id starts with the reversed email domain, so the zone is a reversed prefix
            zone = keyword.strip().lower().lstrip('.')
            if not zone:
                raise CredShedError('Invalid TLD zone (empty)')
            rev = re.escape(zone[::-1])
            query = {'_id': {'$regex': rf'^{rev}\.'}}

        elif query_type == 'username':
            # normalise the term exactly as ingest does so it matches the stored value
            # (clean_utf strips control chars / NFC; then strip + the username translate
            # table + the length cap).  A purely numeric login may have been routed to
            # the phone field, so match either for numeric pivots.
            kw = validation.clean_utf(keyword).strip().translate(Account.strip_from_username)[:Account.max_length_1]
            if contains:
                _require_contains(kw)
                query = {'u': {'$regex': re.escape(kw), '$options': 'i'}}
            elif kw.isdigit():
                query = {'$or': [{'u': kw}, {'t': kw}]}
            else:
                query = {'u': kw}

        elif query_type == 'password':
            # reverse search: "who used this password?" — normalise like ingest
            kw = validation.clean_utf(keyword)[:Account.max_length_1]
            if contains:
                _require_contains(kw)
                query = {'p': {'$regex': re.escape(kw), '$options': 'i'}}
            else:
                query = {'p': kw}

        elif query_type == 'misc':
            # search the misc / context field (victim names, notes, IPs) — the only
            # place Cyrillic/CJK display names live.  Contains-match, case-insensitive;
            # idx_m (sparse) bounds the scan to the docs that actually carry a misc value.
            kw = validation.clean_utf(keyword).strip()
            if not kw:
                raise CredShedError('Empty misc/name search term')
            query = {'m': {'$regex': re.escape(kw[:Account.max_length_2]), '$options': 'i'}}

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
                z = kw.lstrip('.')
                if not z:
                    raise CredShedError('Invalid service zone (empty)')
                rev = re.escape(z[::-1])
                query = {'v': {'$regex': rf'^{rev}\.'}}
            else:
                # service host: the host itself OR any of its subdomains.
                # Split into an exact match + an anchored "host." prefix regex so
                # BOTH arms get index bounds (a single ^...(?:\.|$) regex does not).
                host = validation.extract_host(kw)
                if not host:
                    raise CredShedError(f'Invalid service host: "{keyword}"')
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
        'm': 'misc',   # victim names / context; sparse, so a name search scans only
                       # the (relatively few) docs that actually carry a misc value
    }

    def build_indexes(self, fields=None):
        '''
        Build the given secondary indexes (default u/p/t/v/h/m) in a SINGLE collection
        scan.  MongoDB builds every index named in one createIndexes command from one
        pass over the collection, so building all of them together is ~Nx less I/O than
        create_index-per-field (which re-scans all 580M docs for each index) — the
        single biggest lever on rebuild time, and what the post-ingest --reindex rebuild
        now uses.  Sparse, because most docs populate only a subset of these fields.
        '''
        if fields is None:
            fields = list(self.SECONDARY_INDEX_FIELDS)
        fields = list(fields)
        if not fields:
            return []
        # Give the build more RAM for its in-memory key sort so it spills to disk less
        # (faster).  Best-effort: needs admin, harmless and skipped if not permitted.
        try:
            self.client.admin.command('setParameter', 1, maxIndexBuildMemoryUsageMegabytes=2048)
        except Exception as e:
            log.debug(f'could not raise index-build memory: {e}')
        models = [pymongo.IndexModel([(f, pymongo.ASCENDING)], name=f'idx_{f}', sparse=True)
                  for f in fields]
        names = [f'idx_{f}' for f in fields]
        log.info(f'Building {len(models)} index(es) in ONE collection scan: {names} ...')
        self._op(self.accounts.create_indexes, models)
        log.info(f'Built {len(fields)} index(es): {fields}')
        return fields

    def ensure_indexes(self):
        '''
        Build only the secondary search indexes that are MISSING, skipping ones
        already present (create_index is idempotent, but this keeps the logging
        honest and avoids re-issuing builds).  Called automatically after a bulk
        ingest so the database never ends up un-indexed — a missing index turns
        every username/password/phone/service/hash search into a full collection
        scan, which is exactly what makes a large DB time out.  Returns the list
        of fields it actually built.
        '''
        try:
            have = {ix['name'] for ix in self.accounts.list_indexes()}
        except pymongo.errors.PyMongoError as e:
            log.warning(f'ensure_indexes: could not list indexes: {e}')
            have = set()
        missing = [f for f in self.SECONDARY_INDEX_FIELDS if f'idx_{f}' not in have]
        if not missing:
            log.info('Secondary search indexes already present — nothing to build.')
            return []
        log.info(f'Ensuring secondary search indexes (missing: {missing}) ...')
        return self.build_indexes(missing)

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

    def _sources_signature(self):
        '''
        Cheap fingerprint of the sources collection (count + each source's id /
        account total / finished flag), read from a projection of tiny fields so
        it stays fast even with thousands of sources.  Changes whenever a source
        is added, re-imported, finished or removed — i.e. exactly when the global
        summary needs recomputing.
        '''
        import hashlib
        h = hashlib.md5()
        n = 0
        for s in self.sources.find({}, {'source_id': 1, 'total_accounts': 1,
                                        'import_finished': 1}).sort('source_id', 1):
            n += 1
            h.update(f"{s.get('source_id')}:{int(s.get('total_accounts', 0) or 0)}:"
                     f"{int(bool(s.get('import_finished', True)))};".encode())
        return f"{n}-{h.hexdigest()}"

    def global_summary(self, top_n=15, zones_top=60):
        '''
        Whole-database dashboard snapshot.  The heavy per-source histogram roll-up
        (which grows with the number of sources) is computed once and cached in the
        `meta` collection keyed by a cheap sources fingerprint, so repeated loads —
        across every web worker and across restarts — are a single-document read
        until the sources actually change.  Volatile bits (index list, unique count)
        are always refreshed so they stay live even on a cache hit.
        '''
        sig = None
        try:
            sig = self._sources_signature()
            doc = self.meta.find_one({'_id': 'global_summary'})
            if (doc and doc.get('sig') == sig and doc.get('top_n') == top_n
                    and doc.get('zones_top') == zones_top and doc.get('data')):
                data = doc['data']
                try:
                    data['indexes'] = self.index_info()
                    data['totals']['unique_accounts'] = self.account_count()
                except Exception:
                    pass
                return data
        except pymongo.errors.PyMongoError as e:
            log.warning(f'global_summary cache read: {e}')

        data = self._compute_global_summary(top_n=top_n, zones_top=zones_top)
        if sig is not None:
            try:
                self.meta.replace_one(
                    {'_id': 'global_summary'},
                    {'_id': 'global_summary', 'sig': sig, 'top_n': top_n,
                     'zones_top': zones_top, 'data': data, 'computed_at': datetime.utcnow()},
                    upsert=True)
            except pymongo.errors.PyMongoError as e:
                log.warning(f'global_summary cache write: {e}')
        return data

    def _compute_global_summary(self, top_n=15, zones_top=60):
        '''
        One fast, account-scan-free snapshot of the whole database, assembled
        purely from the per-source histograms in the `sources` collection.
        Powers the statistics dashboard.
        '''
        # 'accounts' sums per-source counts (= rows across sources, which double-counts
        # an account found in N breaches); 'unique_accounts' is the true deduped document
        # count (fast, from collstats) so the dashboard can show the honest headline.
        totals = {'accounts': 0, 'sources': 0, 'email': 0, 'username': 0,
                  'phone': 0, 'with_password': 0, 'with_hash': 0, 'with_service': 0,
                  'filesize': 0, 'unique_accounts': 0}
        try:
            totals['unique_accounts'] = self.account_count()
        except Exception:
            pass
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
        '''
        Roll a {tld: count} histogram up into zones / countries / regions.

        'countries' holds ONLY real country names: generic gTLDs (.com, .net,
        .org) and unresolved zones (.cem) have no country, so they are kept out
        of the country column entirely (they still land in 'zones' and in the
        'regions' column's Generic / Other buckets).  'country_tld' maps each
        country to its largest contributing zone, so the UI can drill a country
        straight into that TLD zone.
        '''
        countries, region_rollup = {}, {}
        country_tld, country_best = {}, {}
        for tld, count in hist.items():
            country, region = regions.region_of(tld)
            region_rollup[region] = region_rollup.get(region, 0) + count
            if country:                              # real country only
                countries[country] = countries.get(country, 0) + count
                if count > country_best.get(country, -1):
                    country_best[country] = count
                    country_tld[country] = tld       # representative zone to drill
        srt = lambda d: sorted(d.items(), key=lambda x: x[1], reverse=True)
        return {
            'zones': srt(hist)[:zones_top],
            'countries': srt(countries),
            'regions': srt(region_rollup),
            'country_tld': country_tld,
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
            region_rollup[region] = region_rollup.get(region, 0) + count
            if country:                              # real country names only
                countries[country] = countries.get(country, 0) + count
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



    @staticmethod
    def _resolve_region(query):
        '''
        Map an investigator's query to (label, kind, zone_set).  `query` may be a TLD
        zone ('uz', 'co.uk') OR a country name ('Uzbekistan', 'United Kingdom'):

          * country name  -> ('United Kingdom', 'country', ['gb', 'uk'])  — every base
            ccTLD that rolls up to that country, so the drill-down covers the WHOLE
            country (all of .uk and .gb and their sub-zones), not just one zone.
          * TLD zone       -> ('co.uk', 'zone', ['co.uk'])

        A base ccTLD prefix match ('^ku\\.') catches every sub-zone (co.uk, gov.uk, …)
        because they all reverse to 'ku.…', so the zone_set stays tiny and index-friendly.
        '''
        q = str(query).strip().lstrip('.')
        cmap = {}
        for cc, (country, _region) in regions.CCTLD.items():
            cmap.setdefault(country.lower(), (country, []))[1].append(cc)
        hit = cmap.get(q.lower())
        if hit:
            return (hit[0], 'country', sorted(set(hit[1])))
        return (q.lower(), 'zone', [q.lower()])

    def tld_detail(self, zone, target='email', top_n=200, sample=30, max_ms=8000, sample_n=5000, all_ms=12000):
        '''
        DFIR drill-down for ONE domain zone ('.kz') OR a whole COUNTRY ('Uzbekistan').
        SCALABLE at ANY DB size:

          * zone account count + the primary breakdown (email domains for an email
            zone / breached services for a service zone) come from the PRECOMPUTED
            per-source histograms — a read of the (few) source docs, NO collection
            scan.
          * the secondary stats (top passwords/usernames, the cross-field hosts,
            coverage %, login split) are estimated from a BOUNDED, index-backed
            SAMPLE of the zone's records and scaled to the zone total.

        So it returns in well under a second whether the zone holds 10k or 100M
        accounts, instead of the old full-zone $facet scan that timed out past a
        few million docs (the dashboard's TLD drill-down was dead at 500M scale).

        target='email'   -> victim geography (email domain in the zone; _id prefix).
        target='service' -> breached-service geography (service host in the zone; 'v').
        '''
        from collections import Counter
        label, kind, zone_set = self._resolve_region(zone)
        # IDN-aware guard on EACH zone (accept .рф/.中国, reject regex metachars / injection)
        for z in zone_set:
            if not z or not re.match(rf'^[a-z0-9{validation._NON_ASCII}][a-z0-9.\-{validation._NON_ASCII}]{{0,23}}$', z):
                raise CredShedError(f'Invalid zone: {z!r}')
        field = 'v' if target == 'service' else '_id'
        clauses = [{field: {'$regex': rf'^{re.escape(z[::-1])}\.'}} for z in zone_set]
        match = clauses[0] if len(clauses) == 1 else {'$or': clauses}   # country = union of its ccTLDs
        coll = self.accounts
        top_n, sample, sample_n = int(top_n), int(sample), int(sample_n)

        def in_region(tld):
            # a histogram zone belongs to this query iff it IS, or is a sub-zone of, one
            # of the target zones (so a country sums all of .uk, .co.uk, .gov.uk, …)
            return bool(tld) and any(tld == z or tld.endswith('.' + z) for z in zone_set)

        # ---- 1. account count + (fallback) primary breakdown ----
        # Pull the zone's count and heavy-hitter services/domains from the CACHED global
        # summary (a single meta-doc read) instead of re-reading every source's histogram
        # on each call -- profiling showed that per-source rollup was ~2.3s of this call,
        # while the group-up below is ~0.08s.  Fall back to the per-source scan only if
        # the summary is unavailable, so correctness never depends on the cache.
        tld_key = 'service_tld_hist' if target == 'service' else 'email_tld_hist'
        prim_key = 'top_services' if target == 'service' else 'top_domains'
        hist_total, primary = 0, {}
        try:
            gs = self.global_summary(top_n=2000, zones_top=3000)
            reg = (gs.get('regions_service' if target == 'service' else 'regions_email') or {})
            for z, c in reg.get('zones', []):
                if in_region(z):
                    hist_total += int(c or 0)
            for k, c in (gs.get(prim_key) or []):
                if in_region(validation.tld_of(k)):
                    primary[k] = primary.get(k, 0) + int(c)
        except Exception as e:
            log.warning(f'tld_detail via summary for {label!r}: {e}; per-source fallback')
            try:
                for s in self.sources.find({}, {tld_key: 1, prim_key: 1}):
                    for zk, zc in self._unescape_keys(s.get(tld_key, {}) or {}).items():
                        if in_region(zk):
                            hist_total += int(zc or 0)
                    for k, c in self._unescape_keys(s.get(prim_key, {}) or {}).items():
                        if in_region(validation.tld_of(k)):
                            primary[k] = primary.get(k, 0) + int(c)
            except pymongo.errors.PyMongoError as e2:
                log.warning(f'tld_detail fallback for {label!r}: {e2}')
        # ---- 2. secondary stats from a bounded, index-backed sample ----
        # From each sampled doc we collect BOTH the service host (field 'v') and the
        # email domain (the reversed _id prefix), un-reversed to their display form, so
        # either can serve as the primary breakdown regardless of target.
        pw, usr, svc, dom = Counter(), Counter(), Counter(), Counter()
        cov = {'with_password': 0, 'with_service': 0, 'with_hash': 0}
        lt = {'email': 0, 'username': 0, 'phone': 0}
        samples, n = [], 0
        try:
            for d in coll.find(match, {'e': 1, 'u': 1, 'p': 1, 'h': 1, 'm': 1, 't': 1, 'v': 1, 's': 1},
                               limit=sample_n, max_time_ms=max_ms):
                n += 1
                if d.get('p'): pw[d['p']] += 1; cov['with_password'] += 1
                if d.get('u'): usr[d['u']] += 1; lt['username'] += 1
                if d.get('h'): cov['with_hash'] += 1
                if d.get('v'): svc[d['v'][::-1]] += 1; cov['with_service'] += 1   # un-reversed service host
                if d.get('e'): lt['email'] += 1
                if d.get('t'): lt['phone'] += 1
                pre = (d.get('_id') or '').split('|')[0]                           # un-reversed email domain
                if pre: dom[pre[::-1]] += 1
                if len(samples) < sample:
                    try: samples.append(Account.from_document(d).json)
                    except Exception: pass
        except pymongo.errors.ExecutionTimeout:
            pass   # best-effort sample — keep what we gathered

        # ---- 3. PRIMARY breakdown (breached services for a service zone / email domains
        # for an email zone).  Prefer an EXACT, COMPLETE index-backed group-up over the
        # whole zone (every service / every domain, not a sample) so an investigator sees
        # ALL affected entities in a region.  Bounded two ways to stay fast: skipped for a
        # zone bigger than COMPLETE_MAX accounts (a giant generic zone like .com, where a
        # group-up would be too heavy and the histogram+sample estimate is used instead),
        # and capped by all_ms as a safety net.  Every ccTLD / country is well under the
        # cap, so it runs in well under a second on an indexed field.
        all_limit = 10000           # generous cap: covers every ccTLD/country completely
        COMPLETE_MAX = 5_000_000    # skip the group-up for a zone bigger than this (use the estimate)

        def complete_group(group_expr):
            # returns (rows, exhaustive) or (None, False) on timeout.  exhaustive is
            # False only when the zone has MORE distinct hosts than the cap (so the
            # list is the top all_limit, not literally all) — true for every country.
            try:
                rows = list(coll.aggregate(
                    [{'$match': match},
                     {'$group': {'_id': group_expr, 'c': {'$sum': 1}}},
                     {'$sort': {'c': -1}},
                     {'$limit': int(all_limit) + 1}],
                    maxTimeMS=int(all_ms), allowDiskUse=True))
                out = [(d['_id'][::-1], int(d['c'])) for d in rows if d.get('_id')][:int(all_limit)]
                return out, (len(rows) <= int(all_limit))
            except pymongo.errors.PyMongoError:
                return None, False   # too big / timed out -> caller falls back to the estimate

        complete, prim_rows = False, None
        if target == 'service':
            prim_rows, complete = (complete_group('$v')
                                   if 0 <= hist_total <= COMPLETE_MAX else (None, False))
        else:
            prim_rows, complete = (complete_group({'$arrayElemAt': [{'$split': ['$_id', '|']}, 0]})
                                   if 0 <= hist_total <= COMPLETE_MAX else (None, False))

        # ---- 4. totals & scale ----
        # When the breakdown is EXACT, the zone's true account count is the SUM of that
        # breakdown (one row per matched document): exact, and self-consistent with the
        # list the investigator sees (its counts add up to this total).  This also makes
        # a country exact regardless of how many minor sub-zones fall past the cached
        # summary's zone cap.  Otherwise: the exact sample count when the whole zone fit
        # in the sample, else the per-source histogram rows-total (an account in N
        # breaches counted N times) scaled from the sample — necessarily an estimate.
        estimated = (n >= sample_n)                      # secondary stats sampled vs exhaustive
        if complete and prim_rows is not None:
            total = sum(c for _, c in prim_rows)         # exact distinct-account count for the zone
        else:
            total = (hist_total or n) if estimated else n
        scale = (total / n) if n else 0
        coverage = {k: int(round(v * scale)) for k, v in cov.items()}
        login_types = {k: int(round(v * scale)) for k, v in lt.items()}
        passwords = pw.most_common(top_n)
        usernames = usr.most_common(top_n)

        # Fallbacks for when the exact group-up was skipped (giant zone) or timed out:
        # merge the precomputed histogram heavy-hitters with the sample's long tail —
        # that tail is why ccTLD / niche zones previously showed an EMPTY list.
        def merge_primary(sample_counter):
            out = dict(primary)                        # exact histogram counts (zone-filtered)
            for name, c in sample_counter.items():
                if name not in out:
                    out[name] = int(round(c * scale))  # scaled estimate for the tail
            return sorted(out.items(), key=lambda x: x[1], reverse=True)[:top_n]

        def sample_list(sample_counter):
            return sorted(((k, int(round(c * scale))) for k, c in sample_counter.items()),
                          key=lambda x: x[1], reverse=True)[:top_n]

        if target == 'service':
            services = prim_rows if prim_rows is not None else merge_primary(svc)  # services hosted IN the zone
            domains = sample_list(dom)                                             # victim email domains (sampled)
        else:
            domains = prim_rows if prim_rows is not None else merge_primary(dom)   # email domains IN the zone
            services = sample_list(svc)                                            # services the victims use (sampled)

        return {
            'zone': label, 'kind': kind, 'target': target, 'total_accounts': total,
            'coverage': coverage, 'login_types': login_types,
            'top_domains': domains, 'top_passwords': passwords,
            'top_services': services, 'top_usernames': usernames,
            'sample': samples, 'partial': False,
            # 'estimated' -> the secondary stats (passwords, usernames, coverage, identity
            # split) are a sample estimate (marked ≈ in the UI).  'complete' -> the primary
            # breakdown is the EXACT, exhaustive set for the zone AND total_accounts is its
            # exact sum (not a histogram estimate); 'total_exact' mirrors that for clarity.
            'estimated': estimated, 'sampled': n,
            'complete': complete,
            'total_exact': bool(complete and prim_rows is not None),
        }

    def domain_detail(self, domain, sample=30, sample_n=5000, max_ms=8000):
        '''
        "Domain exposure" report for ONE exact email domain (e.g. company.com) — the
        count of breached accounts, what share expose a plaintext password / breached
        service / hash, the passwords / usernames / services those accounts carry, WHICH
        breach sources the domain appears in, and sample records.  This is the per-domain
        view a DFIR investigator needs for a client assessment; the TLD drill-down covers
        zones (.com), but a specific domain's accounts live under an _id prefix
        '<reversed-domain>|...', so this matches on that (index-bounded) and estimates
        from a bounded sample, like tld_detail, so it is fast at any domain size.
        '''
        from collections import Counter
        domain = str(domain).strip().lower().lstrip('@').strip('.')   # tolerate @prefix / trailing dot (FQDN)
        if not domain or not validation.is_domain(domain):
            raise CredShedError(f'Invalid domain: {domain!r}')
        coll = self.accounts
        rev = re.escape(domain[::-1])
        match = {'_id': {'$regex': rf'^{rev}\|'}}          # exact domain, uses the _id index
        sample, sample_n = int(sample), int(sample_n)

        pw, usr, svc, srcs = Counter(), Counter(), Counter(), Counter()
        cov = {'with_password': 0, 'with_service': 0, 'with_hash': 0}
        lt = {'email': 0, 'username': 0, 'phone': 0}
        samples, n = [], 0
        breached = []     # (source_count, local_part, source_ids) for accounts in 2+ breaches
        try:
            for d in coll.find(match, {'e': 1, 'u': 1, 'p': 1, 'h': 1, 'm': 1, 't': 1, 'v': 1, 's': 1},
                               limit=sample_n, max_time_ms=max_ms):
                n += 1
                if d.get('p'): pw[d['p']] += 1; cov['with_password'] += 1
                if d.get('u'): usr[d['u']] += 1; lt['username'] += 1
                if d.get('h'): cov['with_hash'] += 1
                if d.get('v'): svc[d['v'][::-1]] += 1; cov['with_service'] += 1
                if d.get('e'): lt['email'] += 1
                if d.get('t'): lt['phone'] += 1
                sset = d.get('s') or []
                for sid in sset:
                    srcs[sid] += 1
                if len(sset) >= 2 and d.get('e'):      # an account seen in multiple breaches
                    breached.append((len(sset), d['e'], sset))
                if len(samples) < sample:
                    try: samples.append(Account.from_document(d).json)
                    except Exception: pass
        except pymongo.errors.ExecutionTimeout:
            pass

        estimated = (n >= sample_n)
        total = n
        if estimated:
            total = 0
            try:
                gs = self.global_summary(top_n=2000, zones_top=3000)
                for dname, c in (gs.get('top_domains') or []):
                    if dname == domain:
                        total = int(c); break
            except Exception:
                pass
            if not total:
                try:
                    total = coll.count_documents(match, maxTimeMS=max_ms)
                except pymongo.errors.PyMongoError:
                    total = n
        scale = (total / n) if n else 0

        # map the breach source_ids this domain appears in to their names
        src_names = {}
        if srcs:
            try:
                for s in self.sources.find({'source_id': {'$in': list(srcs)}},
                                           {'source_id': 1, 'name': 1}):
                    src_names[s.get('source_id')] = str(s.get('name', '')).split('/')[-1] or s.get('source_id')
            except pymongo.errors.PyMongoError:
                pass

        # highest-exposure accounts: the domain's addresses seen in the most breaches
        # (prime credential-stuffing targets for an investigator to prioritise)
        breached.sort(key=lambda x: x[0], reverse=True)
        most_breached = [{'email': f'{e}@{domain}', 'breaches': cnt,
                          'sources': [src_names[s] for s in sset if s in src_names][:12]}
                         for cnt, e, sset in breached[:25]]

        return {
            'domain': domain, 'total_accounts': total, 'estimated': estimated, 'sampled': n,
            'most_breached': most_breached,
            'coverage': {k: int(round(v * scale)) for k, v in cov.items()},
            'login_types': {k: int(round(v * scale)) for k, v in lt.items()},
            'top_passwords': pw.most_common(200),
            'top_usernames': usr.most_common(200),
            'top_services': [(k[::-1], c) for k, c in svc.most_common(200)],
            # only sources that still resolve to a real dataset (skip any dangling
            # source id left by a removed source, so the report lists real breaches)
            'sources': sorted(((src_names[sid], c) for sid, c in srcs.items() if sid in src_names),
                              key=lambda x: x[1], reverse=True),
            'sample': samples, 'partial': False,
        }

    def most_exposed_accounts(self, limit=50, sample_size=15000, min_breaches=3, max_ms=20000):
        '''
        Threat-intel overview: the email accounts seen in the MOST breaches.  A global
        sort by breach count isn't indexable (the provenance array length has no index
        over 500M+ docs), so this draws a bounded RANDOM sample and ranks within it —
        it surfaces REPRESENTATIVE heavily-breached accounts, not a guaranteed absolute
        top-N, and varies slightly between runs (the API caches it for stability).  Each
        result carries the account's breach count and the breach datasets it appears in.
        '''
        try:
            rows = list(self.accounts.aggregate([
                {'$sample': {'size': int(sample_size)}},
                {'$addFields': {'_sc': {'$size': {'$ifNull': ['$s', []]}}}},
                {'$match': {'_sc': {'$gte': int(min_breaches)}, 'e': {'$type': 'string'}}},
                {'$sort': {'_sc': -1}},
                {'$limit': int(limit)},
                {'$project': {'e': 1, 's': 1, '_sc': 1}},
            ], maxTimeMS=int(max_ms), allowDiskUse=True))
        except pymongo.errors.PyMongoError as e:
            log.warning(f'most_exposed_accounts: {e}')
            rows = []
        allsrc = set()
        for r in rows:
            allsrc.update(r.get('s') or [])
        names = {}
        if allsrc:
            try:
                for s in self.sources.find({'source_id': {'$in': list(allsrc)}},
                                           {'source_id': 1, 'name': 1}):
                    names[s['source_id']] = str(s.get('name', '')).split('/')[-1]
            except pymongo.errors.PyMongoError:
                pass
        accounts = []
        for r in rows:
            _id = r.get('_id', '') or ''
            dom = _id.split('|')[0][::-1] if '|' in _id else ''
            accounts.append({
                'email': f"{r.get('e', '')}@{dom}",
                'breaches': int(r.get('_sc', 0)),
                'sources': [names[s] for s in (r.get('s') or []) if s in names][:12],
            })
        return {'accounts': accounts, 'sampled': int(sample_size), 'min_breaches': int(min_breaches)}

    def account_exposure(self, email, max_records=5000, sample=40, max_ms=8000):
        '''
        "Account exposure profile" for ONE exact email address — the per-victim,
        credential-stuffing view a DFIR investigator needs: every breach record tied
        to the address, aggregated into which passwords it REUSED, on which services
        it was breached, which breach datasets it appears in, and any phone/hash on
        file.  (domain_detail profiles a whole organisation; this profiles one person.)

        All of one email's records share the _id prefix '<reversed-domain>|<8-char
        email-hash>' — the first 6 bytes of every record hash are sha1(local-part) —
        so this is an INDEX-BACKED prefix scan on _id, fast at any DB size and for any
        domain (gmail or a tiny company alike), not a collection scan.  The 48-bit
        email-hash can alias a different local-part under the same domain, so each
        record is post-verified against the exact address (same guard as email search).
        '''
        import base64, hashlib
        from collections import Counter
        try:
            acct = Account(email=str(email).strip())
        except AccountCreationError:
            raise CredShedError(f'Invalid email: {email!r}')
        local, domain = acct._email, acct.domain
        if not local or not domain:
            raise CredShedError(f'Invalid email: {email!r}')
        email_norm = f'{local}@{domain}'
        email_hash = base64.b64encode(hashlib.sha1(local.encode()).digest()[:6]).decode()
        prefix = re.escape(domain[::-1] + '|' + email_hash)
        match = {'_id': {'$regex': '^' + prefix}}

        pw, svc, phones = Counter(), Counter(), Counter()
        pw_services = {}            # password -> set of services it was reused on
        src_ids, hashes, samples, n = set(), [], [], 0
        try:
            for d in self.accounts.find(match, {'e': 1, 'u': 1, 'p': 1, 'h': 1, 'm': 1, 't': 1, 'v': 1, 's': 1},
                                        limit=int(max_records), max_time_ms=int(max_ms)):
                if d.get('e') != local:          # 48-bit prefix alias: different local-part, same domain
                    continue
                n += 1
                host = d['v'][::-1] if d.get('v') else None
                if d.get('p'):
                    pw[d['p']] += 1
                    if host:
                        pw_services.setdefault(d['p'], set()).add(host)
                if host: svc[host] += 1
                if d.get('t'): phones[d['t']] += 1
                for h in (d.get('h') or []):
                    if h not in hashes: hashes.append(h)
                for s in (d.get('s') or []): src_ids.add(s)
                if len(samples) < int(sample):
                    try: samples.append(Account.from_document(d).json)
                    except Exception: pass
        except pymongo.errors.ExecutionTimeout:
            pass                                 # best-effort — return what we gathered

        names = []
        if src_ids:
            try:
                for s in self.sources.find({'source_id': {'$in': list(src_ids)}}, {'source_id': 1, 'name': 1}):
                    names.append(str(s.get('name', '')).split('/')[-1] or str(s.get('source_id')))
            except pymongo.errors.PyMongoError:
                pass

        passwords = pw.most_common(200)
        top_pw = passwords[0][0] if passwords else None
        return {
            'email': email_norm,
            'total_records': n,
            'breach_count': len(src_ids),                 # distinct breach datasets (exposure breadth)
            'breach_sources': sorted(set(names)),
            'distinct_passwords': len(pw),
            'passwords': passwords,                       # (password, #records) — reuse is count>1
            'distinct_services': len(svc),
            'services': svc.most_common(500),
            'phones': phones.most_common(10),
            'hashes': hashes[:50],
            'top_password': top_pw,
            # the single most-reused password and how many DISTINCT services it unlocks —
            # the crux of credential-stuffing risk for this victim.
            'top_password_services': (sorted(pw_services.get(top_pw, ())) if top_pw else []),
            'sample': samples,
            'truncated': (n >= int(max_records)),
        }

    def search_records(self, keyword, query_type='auto', limit=100, max_time_ms=10000, mode='exact'):
        '''
        Thin wrapper used by the data-search API: validate the query type, run the
        indexed search, and return account records as plain dicts (human JSON).
        Read-only; honours the same per-field indexes the CLI search uses.

        The scan is time-bounded (max_time_ms) so an un-indexed field search can
        never pin a web worker on a full 19.7M-doc scan; on timeout it returns the
        partial results gathered so far with truncated=True.
        '''
        qt = validation.validate_query_type(keyword, query_type)
        lim = max(1, int(limit))
        # for an EXACT email lookup, verify the reconstructed address of each hit so a
        # rare 48-bit email-hash collision can't surface a different person's record
        expected_email = None
        if qt == 'email':
            try:
                le, de = validation.clean_email(keyword).split('@')[:2]
                le, de = Account.handle_special_email_cases(le, de)
                expected_email = f'{le}@{de}'
            except Exception:
                expected_email = None
        out = []
        truncated = False
        has_more = False
        try:
            # fetch one past the limit so we can tell the caller whether more exist
            # (instead of the UI guessing "capped" when the total happens to == limit)
            for doc in self.search(str(keyword), query_type=qt, limit=lim + 1,
                                   max_time_ms=max_time_ms, mode=mode):
                if expected_email is not None and doc.email != expected_email:
                    continue
                if len(out) >= lim:
                    has_more = True
                    break
                try:
                    out.append(doc.json)
                except Exception:
                    continue
        except pymongo.errors.ExecutionTimeout:
            truncated = True
        return {'query': str(keyword), 'type': qt, 'count': len(out),
                'results': out, 'truncated': truncated, 'has_more': has_more}

    def search_combined(self, conditions, limit=100, max_time_ms=10000):
        '''
        Boolean AND search: every condition must hold on the same account.  Each
        condition is {'type': <query_type>, 'value': <term>, 'mode': exact|contains}.
        e.g. [{'type':'domain','value':'gmail.com'}, {'type':'service','value':'roblox.com'}]
        -> accounts whose email domain is gmail.com AND who were breached on roblox.com.
        Returns the same shape as search_records.
        '''
        if not isinstance(conditions, list):
            raise CredShedError('conditions must be a list of {type, value}')
        conds = [c for c in conditions if isinstance(c, dict) and str(c.get('value', '')).strip()]
        if not conds:
            raise CredShedError('No search conditions given')
        if len(conds) > 8:
            raise CredShedError('Too many conditions (max 8)')
        # str()-coerce type/value so a non-string (e.g. an injected {"$ne":1}) is rejected
        # as an unknown type by validate_query_type rather than crashing on .strip()
        subqueries = [self._build_query(str(c['value']), str(c.get('type', 'auto')),
                                        mode=str(c.get('mode', 'exact')))
                      for c in conds]
        query = subqueries[0] if len(subqueries) == 1 else {'$and': subqueries}
        lim = max(1, int(limit))
        out, truncated, has_more = [], False, False
        try:
            cursor = self._op(self.accounts.find, query, limit=lim + 1, max_time_ms=max_time_ms)
            for result in cursor:
                if len(out) >= lim:
                    has_more = True
                    break
                try:
                    out.append(Account.from_document(result).json)
                except Exception:
                    continue
        except pymongo.errors.ExecutionTimeout:
            truncated = True
        label = ' AND '.join(f"{c.get('type','auto')}={c['value']}" for c in conds)
        return {'query': label, 'type': 'combined', 'conditions': conds, 'count': len(out),
                'results': out, 'truncated': truncated, 'has_more': has_more}

    def bulk_lookup(self, query_type, values, max_time_ms=15000, per_value=50, max_values=1000):
        '''
        Check many selectors of one type at once (e.g. a list of 5,000 emails) and
        report, per value, how many records matched plus a few sample records.  Each
        lookup is index-backed, so a capped batch returns quickly.
        '''
        query_type = str(query_type)
        if not isinstance(values, (list, tuple)):
            raise CredShedError('values must be a list')
        seen, cleaned = set(), []
        for v in values:
            v = str(v).strip()
            if v and v.lower() not in seen:
                seen.add(v.lower())
                cleaned.append(v)
        if not cleaned:
            raise CredShedError('No lookup values given')
        truncated_values = len(cleaned) > max_values
        cleaned = cleaned[:max_values]
        results, total_hits = [], 0
        for v in cleaned:
            try:
                query = self._build_query(v, query_type)
            except CredShedError:
                results.append({'value': v, 'count': 0, 'records': [], 'error': 'invalid'})
                continue
            recs, count = [], 0
            try:
                for doc in self._op(self.accounts.find, query, limit=per_value + 1, max_time_ms=max_time_ms):
                    count += 1
                    if len(recs) < per_value:
                        try:
                            recs.append(Account.from_document(doc).json)
                        except Exception:
                            pass
            except pymongo.errors.ExecutionTimeout:
                pass
            more = count > per_value
            results.append({'value': v, 'count': (per_value if more else count),
                            'has_more': more, 'records': recs})
            total_hits += (1 if count else 0)
        return {'type': query_type, 'values_checked': len(cleaned),
                'values_with_hits': total_hits, 'truncated_values': truncated_values,
                'results': results}


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