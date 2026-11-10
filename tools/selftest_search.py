#!/usr/bin/env python3
"""
End-to-end search self-test against the live credshed database.

Derives probe values from random documents actually present in the DB, then
exercises every search dimension and asserts the probe record comes back.
Also sanity-checks regional statistics and index presence.

Usage:
    <venv>/bin/python tools/selftest_search.py
Exit code 0 = all checks passed.
"""
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
logging.getLogger('credshed').setLevel(logging.ERROR)
from lib.credshed import CredShed          # noqa: E402
from lib.account import Account            # noqa: E402

cs = CredShed()
PASS, FAIL = [], []


def check(name, cond, detail=''):
    (PASS if cond else FAIL).append(name)
    print(f'  [{"PASS" if cond else "FAIL"}] {name}{"  - " + detail if detail else ""}')


def sample(filt, proj):
    # cheap: first matching doc (these fields are common enough that find_one
    # returns quickly; $sample-after-$match would full-scan 16M docs)
    return cs.db.accounts.find_one(filt, proj)


def contains(results, pred):
    return any(pred(a) for a in results)


def main():
    total = cs.db.account_count()
    print(f'DB has {total:,} accounts; indexes: {cs.db.index_info()}\n')
    if total == 0:
        print('Empty DB - ingest first.')
        return 1

    # EMAIL ---------------------------------------------------------------
    doc = sample({'e': {'$exists': True}}, {'e': 1})
    acc = Account.from_document(cs.db.accounts.find_one({'_id': doc['_id']}))
    res = list(cs.search(acc.email, query_type='email', limit=50))
    check('email search returns the probe', contains(res, lambda a: a.email == acc.email), acc.email)

    # DOMAIN --------------------------------------------------------------
    dom = acc.domain
    res = list(cs.search(dom, query_type='domain', limit=50))
    # domain search intentionally includes subdomains (e.g. mail.gmail.com) but
    # must never match siblings (notgmail.com)
    check('domain search returns the domain + subdomains only',
          res and all(a.domain == dom or a.domain.endswith('.' + dom) for a in res), dom)

    # TLD / ZONE ----------------------------------------------------------
    tld = dom.rsplit('.', 1)[-1]
    res = list(cs.search('.' + tld, query_type='tld', limit=50))
    check('tld zone search returns only that zone',
          res and all(a.domain.rsplit('.', 1)[-1] == tld for a in res), '.' + tld)

    # USERNAME ------------------------------------------------------------
    doc = sample({'u': {'$exists': True}}, {'u': 1})
    if doc:
        uname = doc['u']
        res = list(cs.search(uname, query_type='username', limit=50))
        check('username search returns the probe', contains(res, lambda a: a.username == uname),
              uname[:40])

    # PASSWORD (reverse) --------------------------------------------------
    doc = sample({'p': {'$exists': True}}, {'p': 1})
    if doc:
        pw = doc['p']
        res = list(cs.search(pw, query_type='password', limit=50))
        check('password reverse-search returns only that password',
              res and all(a.password == pw for a in res), pw[:40])

    # PHONE ---------------------------------------------------------------
    doc = sample({'t': {'$exists': True}}, {'t': 1})
    if doc:
        tel = doc['t']
        res = list(cs.search(tel, query_type='phone', limit=50))
        check('phone search returns the probe', contains(res, lambda a: a.phone == tel), tel)
        # also with a '+' prefix and separators
        res2 = list(cs.search('+' + tel, query_type='phone', limit=50))
        check('phone search normalizes +prefix', contains(res2, lambda a: a.phone == tel))

    # SERVICE -------------------------------------------------------------
    doc = sample({'v': {'$exists': True}}, {'v': 1})
    if doc:
        host = doc['v'][::-1]  # stored reversed
        res = list(cs.search(host, query_type='service', limit=50))
        check('service search returns the host (and subdomains)',
              res and all(a.service == host or a.service.endswith('.' + host) for a in res), host)
        # negative: a sibling host that shares a suffix must NOT match
        res_neg = list(cs.search(host, query_type='service', limit=200))
        check('service search does not over-match siblings',
              all(a.service == host or a.service.endswith('.' + host) for a in res_neg))

    # REGIONAL STATS ------------------------------------------------------
    rs = cs.db.region_stats(target='email')
    check('region_stats produces zones', bool(rs['zones']),
          f"{len(rs['zones'])} zones")
    check('region_stats rolls up to regions', bool(rs['regions']),
          ', '.join(f'{r}:{c:,}' for r, c in rs['regions'][:3]))
    svc = cs.db.tld_stats(target='service')
    check('service tld_stats produces zones', bool(svc), f'{len(svc)} service zones')

    print(f'\n{len(PASS)} passed, {len(FAIL)} failed'
          + (f'  -> FAILURES: {FAIL}' if FAIL else ''))
    return 0 if not FAIL else 2


if __name__ == '__main__':
    sys.exit(main())
