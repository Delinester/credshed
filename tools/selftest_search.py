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


def sample(filt, proj, hint=None):
    # cheap: first matching doc.  For the sparse-indexed fields we pass hint=
    # 'idx_<field>' so the probe rides the index instead of a full collection
    # scan -- essential at 500M+ scale, where an un-hinted $regex/$exists on a
    # non-headline field would scan for minutes.
    cur = cs.db.accounts.find(filt, proj)
    if hint:
        try:
            cur = cur.hint(hint)
        except Exception:
            pass
    return next(iter(cur.limit(1)), None)


def contains(results, pred):
    return any(pred(a) for a in results)


def probe(field, ok=None, start='0', limit=3000):
    """First indexed value for `field` passing `ok` (default: non-empty and equal to
    its own stripped form, so it round-trips search-side normalization).  Scans a
    bounded slice of idx_<field> so a junk smallest entry (leading space / control
    chars that exist in real breach data) doesn't poison the probe at 500M scale."""
    if ok is None:
        ok = lambda v: bool(v) and v == v.strip()
    q = {field: {'$gte': start}}
    try:
        cur = cs.db.accounts.find(q, {field: 1}).hint(f'idx_{field}').limit(limit)
    except Exception:
        cur = cs.db.accounts.find(q, {field: 1}).limit(limit)
    for d in cur:
        v = d.get(field)
        if v is not None and ok(v):
            return v
    return None


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
    # require a non-whitespace value: a degenerate whitespace-only probe would
    # (correctly) be rejected as an empty search term
    uname = probe('u', lambda v: v == v.strip() and 3 <= len(v) <= 64
                   and "'" not in v and '\\' not in v) or 'admin'
    if uname:
        res = list(cs.search(uname, query_type='username', limit=50))
        check('username search returns the probe', contains(res, lambda a: a.username == uname),
              uname[:40])

    # PASSWORD (reverse) --------------------------------------------------
    pw = probe('p', lambda v: v == v.strip() and 4 <= len(v) <= 64) or '123456'
    if pw:
        res = list(cs.search(pw, query_type='password', limit=50))
        check('password reverse-search returns only that password',
              res and all(a.password == pw for a in res), pw[:40])

    # PHONE ---------------------------------------------------------------
    tel = probe('t', lambda v: v == v.strip() and v.isdigit() and 8 <= len(v) <= 15 and len(set(v)) >= 3)
    if tel:
        res = list(cs.search(tel, query_type='phone', limit=50))
        check('phone search returns the probe', contains(res, lambda a: a.phone == tel), tel)
        # also with a '+' prefix and separators
        res2 = list(cs.search('+' + tel, query_type='phone', limit=50))
        check('phone search normalizes +prefix', contains(res2, lambda a: a.phone == tel))

    # SERVICE -------------------------------------------------------------
    hostv = probe('v', lambda v: v == v.strip() and '.' in v and ' ' not in v and v.isprintable())
    if hostv:
        host = hostv[::-1]  # stored reversed
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
