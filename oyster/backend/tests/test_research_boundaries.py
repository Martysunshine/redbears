import asyncio
import time
from types import SimpleNamespace
import pytest
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
import config
from routers.research import router
from routers.investigation import promote_finding, PromoteFindingRequest
from services.auth_service import require_admin
from services.detection.evaluator import validate_detection
from services.investigation import store
from services.scenarios.base import ScopedClient, ScopeViolation, BudgetExceeded


def test_research_router_requires_operator(monkeypatch):
    monkeypatch.setattr(config,'DISABLE_AUTH',False)
    app=FastAPI(); app.include_router(router,dependencies=[Depends(require_admin)])
    with TestClient(app) as c:
        assert c.get('/research/status').status_code==401
        assert c.post('/research/runs',json={'question':'Access control evidence'}).status_code==401


def test_absent_telemetry_is_inconclusive():
    instance=SimpleNamespace(telemetry=None)
    r=asyncio.run(validate_detection(instance,'idor_improved',scenario_context={},include_benign_traffic=False))
    assert r.detection=='inconclusive' and r.false_positive_on_benign is None


def test_target_and_budget_enforced_without_model():
    async def run():
        client=ScopedClient(base_url='http://127.0.0.1:31101',max_requests=0,deadline=time.time()+1)
        try:
            with pytest.raises(ScopeViolation):await client.request('GET','https://example.org/')
            with pytest.raises(BudgetExceeded):await client.request('GET','/rest/basket/1')
        finally:await client.aclose()
    asyncio.run(run())


def test_unverified_finding_cannot_be_promoted(monkeypatch):
    monkeypatch.setattr(store,'get_investigation',lambda _: {'simulation':'inconclusive'})
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as e:
        asyncio.run(promote_finding(PromoteFindingRequest(investigation_id='x',title='Unverified')))
    assert e.value.status_code==409


def test_cancelled_provision_waits_and_cleans_its_instance(monkeypatch):
    from routers.research import provision_owned
    from services.lab import provisioner
    cleaned=[]
    monkeypatch.setattr(provisioner,'cleanup_instance',lambda ident:cleaned.append(ident))
    def provision():
        time.sleep(.03)
        return SimpleNamespace(id='owned-instance')
    async def run():
        task=asyncio.create_task(provision_owned(provision))
        await asyncio.sleep(.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):await task
    asyncio.run(run())
    assert cleaned==['owned-instance']
