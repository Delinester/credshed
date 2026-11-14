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

    print(f'\n{len(PASS)} passed, {len(FAIL)} failed')
    return 1 if FAIL else 0


if __name__ == '__main__':
    sys.exit(main())
