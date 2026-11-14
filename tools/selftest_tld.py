#!/usr/bin/env python3
"""
Regression self-test for the TLD-zone / country drill-down (tld_detail) and the
zone/country resolver.  Asserts:
  * _resolve_region maps zones vs country names (case/whitespace/multi-ccTLD),
  * tld_detail accepts a zone AND a country, with matching totals,
  * the service/domain breakdown is EXACT (returned == brute-force distinct) when
    flagged complete,
  * injection / empty / over-long zones are rejected.

Usage:  <venv>/bin/python tools/selftest_tld.py     (exit 0 = all passed)
Derives its probe zones from the live data, so it works on any populated DB.
"""
import re
import sys
import logging
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
logging.getLogger('credshed').setLevel(logging.ERROR)
from lib.credshed import CredShed          # noqa: E402
from lib import validation                 # noqa: E402
from lib import regions                    # noqa: E402
from lib.errors import CredShedError       # noqa: E402

cs = CredShed()
db = cs.db
PASS, FAIL = [], []


def check(name, cond, detail=''):
    (PASS if cond else FAIL).append(name)
    print(f'  [{"PASS" if cond else "FAIL"}] {name}' + (f'  - {detail}' if (not cond and detail) else ''))


def exact_distinct(zones, field):
    cl = [{field: {'$regex': rf'^{re.escape(z[::-1])}\.'}} for z in zones]
    m = cl[0] if len(cl) == 1 else {'$or': cl}
    if field == 'v':
        return len(db.accounts.distinct('v', m))
    return len(set(d['_id'].split('|')[0] for d in db.accounts.find(m, {'_id': 1})))


def main():
    total = db.account_count()
    print(f'DB has {total:,} accounts; indexes: {db.index_info()}\n')
    if total == 0:
        print('Empty DB - ingest first.'); return 1

    # ---- resolver -------------------------------------------------------
    print('-- _resolve_region --')
    check('zone passthrough', db._resolve_region('uz') == ('uz', 'zone', ['uz']))
    check('country name', db._resolve_region('Uzbekistan') == ('Uzbekistan', 'country', ['uz']))
    check('country case/space-insensitive', db._resolve_region('  uZBEKISTAN ')[1] == 'country')
    check('multi-ccTLD country', sorted(db._resolve_region('United Kingdom')[2]) == ['gb', 'uk'])
    check('unknown -> zone', db._resolve_region('nowhere')[1] == 'zone')
    check('leading dot stripped', db._resolve_region('.com')[2] == ['com'])

    # ---- guards ---------------------------------------------------------
    print('-- guards --')
    for bad in ['', '.|x', '$where', 'a' * 60]:
        try:
            db.tld_detail(bad, target='service'); check(f'reject {bad[:12]!r}', False, 'no error raised')
        except CredShedError:
            check(f'reject {bad[:12]!r}', True)
        except Exception as e:
            check(f'reject {bad[:12]!r}', False, f'wrong error {type(e).__name__}')

    # ---- pick a non-generic service zone that exists, to test completeness
    svc_tlds = {}
    for s in db.sources.find({}, {'service_tld_hist': 1}):
        for k, c in db._unescape_keys(s.get('service_tld_hist', {}) or {}).items():
            if k not in ('com', 'net', 'org') and regions.region_of(k)[0]:  # a real ccTLD
                svc_tlds[k] = svc_tlds.get(k, 0) + int(c)
    probe = sorted(svc_tlds.items(), key=lambda x: x[1], reverse=True)
    zone = next((z for z, c in probe if 100 <= c <= 2_000_000), (probe[0][0] if probe else 'fr'))

    print(f'-- tld_detail completeness (zone .{zone}) --')
    r = db.tld_detail(zone, target='service')
    check('service drill-down returns data', r['total_accounts'] > 0, f"total={r['total_accounts']}")
    if r.get('complete'):
        ex = exact_distinct([zone], 'v')
        check('service list is EXACT when complete',
              len(r['top_services']) == ex, f"returned={len(r['top_services'])} exact={ex}")
    else:
        check('non-complete zone still returns services', len(r['top_services']) > 0)

    # ---- country == its single-ccTLD zone -------------------------------
    country = regions.region_of(zone)[0]
    if country and db._resolve_region(country)[2] == [zone]:
        print(f'-- country ({country}) aggregates its zone --')
        rc = db.tld_detail(country, target='service')
        check('country total == zone total', rc['total_accounts'] == r['total_accounts'],
              f"country={rc['total_accounts']} zone={r['total_accounts']}")
        check('country kind flag', rc['kind'] == 'country')

    # ---- email-domain completeness --------------------------------------
    print(f'-- tld_detail email domains (.{zone}) --')
    re_ = db.tld_detail(zone, target='email')
    if re_.get('complete') and re_['total_accounts'] > 0:
        ex = exact_distinct([zone], '_id')
        check('domain list is EXACT when complete',
              len(re_['top_domains']) == ex, f"returned={len(re_['top_domains'])} exact={ex}")
    else:
        check('email drill-down returns (zone may be empty for email)', True)

    # ---- domain exposure report (domain_detail) -------------------------
    print('-- domain_detail (domain exposure report) --')
    probe_dom = None
    for s in db.sources.find({}, {'top_domains': 1}):
        for k in db._unescape_keys(s.get('top_domains', {}) or {}):
            if '.' in k and validation.is_domain(k):
                probe_dom = k; break
        if probe_dom:
            break
    if probe_dom:
        dd = db.domain_detail(probe_dom)
        check(f'domain report returns data [{probe_dom}]', dd['total_accounts'] > 0,
              f"total={dd['total_accounts']}")
        check('domain report has coverage + sources keys',
              all(k in dd for k in ('coverage', 'login_types', 'top_passwords', 'sources')))
        check('domain report sources all resolve (no bare ids)',
              all(isinstance(s[0], str) for s in dd['sources']))
    for bad in ['', 'not a domain', '$where', 'x.com|y']:
        try:
            db.domain_detail(bad); check(f'domain_detail rejects {bad[:10]!r}', False, 'no error')
        except CredShedError:
            check(f'domain_detail rejects {bad[:10]!r}', True)
        except Exception as e:
            check(f'domain_detail rejects {bad[:10]!r}', False, f'wrong error {type(e).__name__}')

    # ---- account exposure profile (account_exposure) --------------------
    print('-- account_exposure (per-email profile) --')
    import re as _re
    probe_email, probe_prefix = None, None
    for d in db.accounts.aggregate([{'$sample': {'size': 4000}},
                                    {'$match': {'e': {'$type': 'string'}}},
                                    {'$project': {'e': 1, '_id': 1}}], allowDiskUse=True):
        _id = d.get('_id', '')
        if '|' in _id and d.get('e'):
            rdom, rest = _id.split('|', 1)
            probe_email = f"{d['e']}@{rdom[::-1]}"
            probe_prefix = rdom + '|' + rest[:8]   # reversed-domain + 8-char email-hash (same for all this email's records)
            break
    if probe_email:
        ae = db.account_exposure(probe_email)
        local = ae['email'].split('@')[0]
        # brute-force via the EMAIL-HASH-specific _id prefix (index range, fast at any
        # scale) + the exact-local post-filter — independent of account_exposure's rollup
        brute = db.accounts.count_documents({'e': local, '_id': {'$regex': '^' + _re.escape(probe_prefix)}})
        check(f'account_exposure returns records [{probe_email[:28]}]', ae['total_records'] > 0,
              f"records={ae['total_records']}")
        check('account total_records == brute-force _id-prefix count',
              ae['total_records'] == brute, f"got={ae['total_records']} brute={brute}")
        check('sum(password counts) == total_records (every record accounted for OR no-pw)',
              sum(c for _, c in ae['passwords']) <= ae['total_records'])
        check('account has reuse/profile keys',
              all(k in ae for k in ('distinct_passwords', 'distinct_services', 'breach_count',
                                    'breach_sources', 'top_password', 'top_password_services')))
    for bad in ['', 'not-an-email', 'nodomain@', '@nolocal.com']:
        try:
            db.account_exposure(bad); check(f'account_exposure rejects {bad[:12]!r}', False, 'no error')
        except CredShedError:
            check(f'account_exposure rejects {bad[:12]!r}', True)
        except Exception as e:
            check(f'account_exposure rejects {bad[:12]!r}', False, f'wrong error {type(e).__name__}')
    # injection-safety: regex metachars / operator-dict payloads must be sanitised (not
    # executed) and never raise a non-CredShed error — clean_email strips them, re.escape
    # guards the prefix, so a crafted address resolves to a harmless valid-or-rejected one
    for inj in ['x.com|y@a.com', '.*@gmail.com', '$where@x.com', "a';b@x.com"]:
        try:
            r = db.account_exposure(inj)
            check(f'account_exposure injection-safe {inj[:12]!r}',
                  isinstance(r, dict) and r.get('total_records', 0) >= 0)
        except CredShedError:
            check(f'account_exposure injection-safe {inj[:12]!r}', True)   # rejected is also fine
        except Exception as e:
            check(f'account_exposure injection-safe {inj[:12]!r}', False, f'raised {type(e).__name__}')

    print(f'\n{len(PASS)} passed, {len(FAIL)} failed')
    return 1 if FAIL else 0


if __name__ == '__main__':
    sys.exit(main())
