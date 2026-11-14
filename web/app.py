#!/usr/bin/env python3
"""
Credshed statistics dashboard - backend.

A small, READ-ONLY API that serves aggregate statistics only (counts, regional
breakdowns, top lists).  It deliberately exposes NO per-account / credential
data - there is no search or record endpoint here.

All numbers come from DB.global_summary(), which reads the per-source
histograms (never scans the accounts collection), so the dashboard stays fast
even on a billion-row database.

Run:
    <venv>/bin/uvicorn web.app:app --host 0.0.0.0 --port 8000
or:
    <venv>/bin/python -m web.app          # uses CREDSHED_WEB_HOST/PORT env vars
"""
import os
import sys
import time
import logging
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import FastAPI, Request                  # noqa: E402
from fastapi.responses import JSONResponse, FileResponse  # noqa: E402
from fastapi.staticfiles import StaticFiles           # noqa: E402

from lib.credshed import CredShed                     # noqa: E402
from lib.errors import CredShedError                  # noqa: E402

logging.getLogger('credshed').setLevel(logging.WARNING)

STATIC_DIR = Path(__file__).resolve().parent / 'static'
CACHE_TTL = int(os.environ.get('CREDSHED_WEB_CACHE', '30'))  # seconds

app = FastAPI(title='Credshed Statistics', docs_url='/api/docs', version='2.1')

_cs = None
_cache = {'t': 0.0, 'data': None}
_src_cache = {}   # source_id -> (timestamp, detail dict)
_tld_cache = {}   # (zone,target,top,sample) -> (timestamp, detail dict); caches even a
                  # partial/giant-zone result so repeated .com clicks aren't 10s each

# How deep the cached aggregation goes (the dashboard's "Show all" browses this).
FULL_TOP = 2000      # top services / domains / password base-words
FULL_ZONES = 3000    # TLD zones per target
# Hard ceiling on a single record-search fetch.  The dashboard offers 100…50000 plus
# "All", which sends limit<=0 and resolves to this.  It bounds the response size /
# worker memory while still letting an investigator pull far more than the old 1000.
SEARCH_MAX = 100000


def credshed():
    global _cs
    if _cs is None:
        _cs = CredShed()
    return _cs


def full(ttl=CACHE_TTL):
    # tiny in-process cache so rapid reloads don't re-aggregate
    now = time.monotonic()
    if _cache['data'] is not None and (now - _cache['t']) < ttl:
        return _cache['data']
    data = credshed().db.global_summary(top_n=FULL_TOP, zones_top=FULL_ZONES)
    _cache['t'] = now
    _cache['data'] = data
    return data


def compact(d, n=15):
    '''a small initial payload derived from the full aggregation'''
    def reg(r):
        return {'regions': r['regions'], 'countries': r['countries'][:n * 2],
                'zones': r['zones'][:n], 'country_tld': r.get('country_tld', {})}
    return {
        'totals': d['totals'], 'indexes': d['indexes'], 'formats': d['formats'],
        'sources': d['sources'],
        'top_domains': d['top_domains'][:n], 'top_services': d['top_services'][:n],
        'top_password_basewords': d['top_password_basewords'][:n],
        'top_passwords': d.get('top_passwords', [])[:n],
        'password_lengths': d.get('password_lengths', []),
        'regions_email': reg(d['regions_email']), 'regions_service': reg(d['regions_service']),
    }


@app.get('/api/summary')
def api_summary():
    try:
        return JSONResponse(compact(full()))
    except CredShedError as e:
        return JSONResponse({'error': str(e)}, status_code=503)
    except Exception as e:  # pragma: no cover
        return JSONResponse({'error': f'{type(e).__name__}: {e}'}, status_code=500)


@app.get('/api/list')
def api_list(metric: str, target: str = 'email'):
    '''full (deep) list for one metric — powers the dashboard "Show all" expander.'''
    try:
        d = full()
        rkey = 'regions_service' if target == 'service' else 'regions_email'
        items = {
            'countries': d[rkey]['countries'],
            'zones': d[rkey]['zones'],
            'regions': d[rkey]['regions'],
            'services': d['top_services'],
            'domains': d['top_domains'],
            'passwords': d['top_password_basewords'],
            'pwactual': d.get('top_passwords', []),
        }.get(metric)
        if items is None:
            return JSONResponse({'error': f'unknown metric {metric!r}'}, status_code=400)
        return JSONResponse({'metric': metric, 'target': target, 'count': len(items), 'items': items})
    except CredShedError as e:
        return JSONResponse({'error': str(e)}, status_code=503)
    except Exception as e:  # pragma: no cover — match the other routes' 500 surface
        return JSONResponse({'error': f'{type(e).__name__}: {e}'}, status_code=500)


@app.get('/api/source/{source_id}')
def api_source(source_id: int):
    '''Detailed statistics for one ingested dataset (source) — powers the modal.'''
    # a source_id outside int64 can't exist and makes Mongo raise; answer 404 cleanly
    if not (-2**63 <= source_id < 2**63):
        return JSONResponse({'error': f'No source with id {source_id}'}, status_code=404)
    try:
        now = time.time()
        hit = _src_cache.get(source_id)
        if hit and (now - hit[0]) < CACHE_TTL:
            return JSONResponse(hit[1])
        data = credshed().db.source_detail(source_id, top_n=FULL_TOP, zones_top=FULL_ZONES)
        if len(_src_cache) >= 256:          # bound the cache (evict the oldest entry)
            _src_cache.pop(min(_src_cache, key=lambda k: _src_cache[k][0]), None)
        _src_cache[source_id] = (now, data)
        return JSONResponse(data)
    except CredShedError as e:
        return JSONResponse({'error': str(e)}, status_code=404)
    except Exception as e:  # pragma: no cover
        return JSONResponse({'error': f'{type(e).__name__}: {e}'}, status_code=500)


@app.get('/api/search')
def api_search(q: str, type: str = 'auto', limit: int = 100, mode: str = 'exact'):
    '''
    DFIR data search: return actual account records matching a query.  Supported
    types: email, domain, tld/zone, username, password, hash, phone, service, misc
    (auto-detected when type=auto).  mode=contains does a substring match on the
    free-text fields (username/password/misc).  Read-only; uses the per-field indexes.

    This endpoint intentionally returns credential records (not just stats): the
    dashboard is for authorised investigators on an internal, access-controlled
    network, where seeing the underlying data is the point.
    '''
    n = int(limit)
    limit = SEARCH_MAX if n <= 0 else max(1, min(n, SEARCH_MAX))   # <=0 means "All"
    md = 'contains' if mode == 'contains' else 'exact'
    # bigger fetches get a longer (still bounded) scan budget; an indexed search
    # finishes fast, an un-indexed one still hits the ceiling and returns partial
    max_ms = min(30000, max(10000, limit * 2))
    try:
        data = credshed().db.search_records(q, query_type=type, limit=limit, max_time_ms=max_ms, mode=md)
        data['limit'] = limit
        return JSONResponse(data)
    except CredShedError as e:
        return JSONResponse({'error': str(e)}, status_code=400)
    except Exception as e:  # pragma: no cover
        return JSONResponse({'error': f'{e.__class__.__name__}: {e}'}, status_code=500)


@app.post('/api/combined')
async def api_combined(request: Request):
    '''Boolean AND search: every condition must hold on the same account.
    Body: {"conditions":[{"type","value","mode"}...], "limit":N}.'''
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({'error': 'invalid JSON body'}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({'error': 'body must be a JSON object'}, status_code=400)
    conditions = body.get('conditions') or []
    try:
        n = int(body.get('limit', 100) or 100)
    except (TypeError, ValueError):
        n = 100
    limit = SEARCH_MAX if n <= 0 else max(1, min(n, SEARCH_MAX))
    max_ms = min(30000, max(10000, limit * 2))
    try:
        data = credshed().db.search_combined(conditions, limit=limit, max_time_ms=max_ms)
        data['limit'] = limit
        return JSONResponse(data)
    except CredShedError as e:
        return JSONResponse({'error': str(e)}, status_code=400)
    except Exception as e:  # pragma: no cover
        return JSONResponse({'error': f'{e.__class__.__name__}: {e}'}, status_code=500)


@app.post('/api/bulk')
async def api_bulk(request: Request):
    '''Bulk lookup: check many selectors of one type at once.
    Body: {"type":"email", "values":[...], "per_value":N}.'''
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({'error': 'invalid JSON body'}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({'error': 'body must be a JSON object'}, status_code=400)
    qtype = body.get('type', 'auto')
    values = body.get('values') or []
    try:
        per_value = max(1, min(int(body.get('per_value', 50) or 50), 500))
    except (TypeError, ValueError):
        per_value = 50
    try:
        data = credshed().db.bulk_lookup(qtype, values, per_value=per_value)
        return JSONResponse(data)
    except CredShedError as e:
        return JSONResponse({'error': str(e)}, status_code=400)
    except Exception as e:  # pragma: no cover
        return JSONResponse({'error': f'{e.__class__.__name__}: {e}'}, status_code=500)


@app.get('/api/tld/{zone}')
def api_tld(zone: str, target: str = 'email', top: int = 200, sample: int = 30):
    '''Drill-down statistics + sample records for one domain zone (e.g. ".kz").'''
    top = max(1, min(int(top), 2000))
    sample = max(0, min(int(sample), 200))
    tgt = 'service' if target == 'service' else 'email'
    key = (zone, tgt, top, sample)
    now = time.time()
    hit = _tld_cache.get(key)
    if hit and (now - hit[0]) < CACHE_TTL:
        return JSONResponse(hit[1])
    try:
        data = credshed().db.tld_detail(zone, target=tgt, top_n=top, sample=sample)
        if len(_tld_cache) >= 256:           # bound the cache (evict the oldest entry)
            _tld_cache.pop(min(_tld_cache, key=lambda k: _tld_cache[k][0]), None)
        _tld_cache[key] = (now, data)
        return JSONResponse(data)
    except CredShedError as e:
        return JSONResponse({'error': str(e)}, status_code=400)
    except Exception as e:  # pragma: no cover
        return JSONResponse({'error': f'{e.__class__.__name__}: {e}'}, status_code=500)


@app.get('/api/domain/{domain}')
def api_domain(domain: str, sample: int = 30):
    '''Domain exposure report: stats + breach sources + samples for one exact email domain.'''
    sample = max(0, min(int(sample), 200))
    key = ('__domain__', domain, sample)
    now = time.time()
    hit = _tld_cache.get(key)
    if hit and (now - hit[0]) < CACHE_TTL:
        return JSONResponse(hit[1])
    try:
        data = credshed().db.domain_detail(domain, sample=sample)
        if len(_tld_cache) >= 256:
            _tld_cache.pop(min(_tld_cache, key=lambda k: _tld_cache[k][0]), None)
        _tld_cache[key] = (now, data)
        return JSONResponse(data)
    except CredShedError as e:
        return JSONResponse({'error': str(e)}, status_code=400)
    except Exception as e:  # pragma: no cover
        return JSONResponse({'error': f'{e.__class__.__name__}: {e}'}, status_code=500)


@app.get('/api/health')
def api_health():
    try:
        n = credshed().db.account_count()
        return {'status': 'ok', 'accounts': n}
    except Exception as e:
        return JSONResponse({'status': 'error', 'detail': str(e)}, status_code=503)


@app.get('/')
def index():
    return FileResponse(str(STATIC_DIR / 'index.html'))


# serve the rest of the static assets (there are none beyond index.html by
# default, but this keeps the app extensible)
if STATIC_DIR.is_dir():
    app.mount('/static', StaticFiles(directory=str(STATIC_DIR)), name='static')


if __name__ == '__main__':
    import uvicorn
    host = os.environ.get('CREDSHED_WEB_HOST', '0.0.0.0')
    port = int(os.environ.get('CREDSHED_WEB_PORT', '8000'))
    uvicorn.run(app, host=host, port=port)
