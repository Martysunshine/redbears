"""Local-only standalone demo; no proprietary dependencies or private assets."""
import os
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from .api import Runs, router_for

load_dotenv(override=False)
runs = Runs(Path(os.getenv('REDBEARS_RESEARCH_DATA', str(Path.home() / '.redbears-research'))))

@asynccontextmanager
async def lifespan(app):
    yield
    await runs.close()

app = FastAPI(title='Red Bears Research', lifespan=lifespan)

@app.middleware('http')
async def local_only(request: Request, call_next):
    host = request.url.hostname
    origin = request.headers.get('origin')
    if host not in ('127.0.0.1', 'localhost', '::1') or (request.client and request.client.host not in ('127.0.0.1', '::1', 'testclient')):
        return JSONResponse({'detail': 'This demo is loopback-only.'}, status_code=403)
    if origin and (urlsplit(origin).hostname not in ('127.0.0.1', 'localhost', '::1') or urlsplit(origin).netloc != request.url.netloc):
        return JSONResponse({'detail': 'Cross-origin requests are refused.'}, status_code=403)
    if request.headers.get('sec-fetch-site') == 'cross-site':
        return JSONResponse({'detail': 'Cross-site requests are refused.'}, status_code=403)
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'"
    return response

app.include_router(router_for(runs))
STATIC = Path(__file__).parent / 'static'

@app.get('/')
async def index():
    return FileResponse(STATIC / 'index.html')

@app.get('/app.js')
async def js():
    return FileResponse(STATIC / 'app.js', media_type='text/javascript')

@app.get('/app.css')
async def css():
    return FileResponse(STATIC / 'app.css', media_type='text/css')
