"""Reusable router; host application supplies authentication and optional lab callback."""
from __future__ import annotations
import asyncio
import json
import os
import re
import time
import uuid
from pathlib import Path
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from .engine import Research, now
from .providers import Providers


class StartRequest(BaseModel):
    question: str = Field(min_length=10, max_length=3000)


class Runs:
    def __init__(self, root: Path, providers=None, lab=None):
        self.root = root
        self.providers = providers or Providers
        self.lab = lab
        self.records = {}
        self.tasks = {}
        self.last_start = 0.

    def save(self, record):
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        dest = self.root / (record['id'] + '.json')
        temp = dest.with_suffix('.tmp')
        fd = os.open(temp, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'w') as f:
            json.dump(record, f, ensure_ascii=False)
        temp.replace(dest)

    def get(self, run_id):
        if not re.fullmatch('[0-9a-f]{24}', run_id):
            raise HTTPException(404, 'No such research run.')
        if run_id not in self.records:
            try:
                self.records[run_id] = json.loads((self.root / (run_id + '.json')).read_text())
                r = self.records[run_id]
                if r['status'] in ('running', 'lab_running'):
                    r['status'] = 'interrupted'
                    r['events'].append({'seq': len(r['events']) + 1, 'at': now(), 'type': 'stopped', 'reason': 'Server restarted; this run was interrupted.'})
                    self.save(r)
            except (OSError, ValueError):
                raise HTTPException(404, 'No such research run.') from None
        return self.records[run_id]

    def busy(self):
        return any(not t.done() for t in self.tasks.values())

    async def close(self):
        for task in self.tasks.values():
            task.cancel()
        await asyncio.gather(*self.tasks.values(), return_exceptions=True)


def router_for(runs: Runs):
    router = APIRouter(prefix='/research', tags=['research'])

    @router.get('/status')
    async def status():
        p = runs.providers()
        return {'missing': p.missing(), 'model': p.model, 'lab_available': runs.lab is not None,
                'provider': 'Nebius Token Factory', 'retrieval': 'Tavily'}

    @router.post('/runs', status_code=202)
    async def start(body: StartRequest):
        if runs.busy() or time.monotonic() - runs.last_start < 2:
            raise HTTPException(429, 'One run at a time; wait briefly before retrying.')
        runs.last_start = time.monotonic()
        p = runs.providers()
        record = {'id': uuid.uuid4().hex[:24], 'question': '', 'created_at': now()}
        engine = Research(p, record, runs.save)
        record['question'] = engine.clean(body.question)
        engine.messages[-1]['content'] = record['question']
        runs.records[record['id']] = record
        runs.save(record)
        runs.tasks[record['id']] = asyncio.create_task(engine.run())
        return record

    @router.get('/runs/{run_id}')
    async def get(run_id: str):
        return runs.get(run_id)

    @router.post('/runs/{run_id}/cancel')
    async def cancel(run_id: str):
        record = runs.get(run_id)
        if record['status'] == 'lab_running':
            raise HTTPException(409, 'The bounded lab test is finishing; it cleans up its own instance.')
        task = runs.tasks.get(run_id)
        if task and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        return record

    @router.post('/runs/{run_id}/lab', status_code=202)
    async def lab(run_id: str):
        record = runs.get(run_id)
        proposal = (record.get('report') or {}).get('scenario_id')
        if runs.lab is None:
            raise HTTPException(409, 'Research-only host; isolated lab is unavailable.')
        if not proposal or record['status'] != 'completed':
            raise HTTPException(409, 'A completed evidence-backed report must propose a supported scenario first.')
        if record.get('lab') or runs.busy():
            raise HTTPException(409, 'Lab already run or another investigation is active.')
        record['status'] = 'lab_running'
        def event(kind, **data):
            record['events'].append({'seq': len(record['events']) + 1, 'at': now(), 'type': kind, **data})
            runs.save(record)
        async def execute():
            event('lab_started', scenario_id=proposal)
            try:
                record['lab'] = await runs.lab(proposal, event)
                record['status'] = 'completed'
                event('lab_finished', result=record['lab'])
            except asyncio.CancelledError:
                record['status'] = 'interrupted'
                event('lab_unavailable', detail='Server shutdown interrupted lab verification.')
            except Exception:
                record['status'] = 'completed'
                event('lab_unavailable', detail='Lab unavailable or validation failed; no successful result claimed.')
        runs.tasks[run_id] = asyncio.create_task(execute())
        return record

    return router
