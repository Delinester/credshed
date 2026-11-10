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


def credshed():
    global _cs
    if _cs is None:
        _cs = CredShed()
    return _cs


def summary(ttl=CACHE_TTL):
    # tiny in-process cache so rapid reloads don't re-aggregate
    now = time.monotonic()
    if _cache['data'] is not None and (now - _cache['t']) < ttl:
        return _cache['data']
    data = credshed().db.global_summary()
    _cache['t'] = now
    _cache['data'] = data
    return data


@app.get('/api/summary')
def api_summary():
    try:
        return JSONResponse(summary())
    except CredShedError as e:
        return JSONResponse({'error': str(e)}, status_code=503)
    except Exception as e:  # pragma: no cover
        return JSONResponse({'error': f'{type(e).__name__}: {e}'}, status_code=500)


@app.get('/api/regions')
def api_regions(target: str = 'email'):
    try:
        key = 'regions_service' if target == 'service' else 'regions_email'
        return JSONResponse(summary()[key])
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
