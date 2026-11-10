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

from fastapi import FastAPI                           # noqa: E402
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

# How deep the cached aggregation goes (the dashboard's "Show all" browses this).
FULL_TOP = 2000      # top services / domains / password base-words
FULL_ZONES = 3000    # TLD zones per target


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
        return {'regions': r['regions'], 'countries': r['countries'][:n * 2], 'zones': r['zones'][:n]}
    return {
        'totals': d['totals'], 'indexes': d['indexes'], 'formats': d['formats'],
        'sources': d['sources'],
        'top_domains': d['top_domains'][:n], 'top_services': d['top_services'][:n],
        'top_password_basewords': d['top_password_basewords'][:n],
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
        }.get(metric)
        if items is None:
            return JSONResponse({'error': f'unknown metric {metric!r}'}, status_code=400)
        return JSONResponse({'metric': metric, 'target': target, 'count': len(items), 'items': items})
    except CredShedError as e:
        return JSONResponse({'error': str(e)}, status_code=503)


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
