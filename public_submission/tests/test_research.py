import asyncio
import copy
import json
from pathlib import Path
import httpx
import pytest
from redbears_research.engine import Research, Limits
from redbears_research.providers import Providers, ProviderError, public_url
from redbears_research.api import Runs, router_for
from fastapi import FastAPI
from fastapi.testclient import TestClient

PASSAGE = 'Authorization must be enforced on every request. Deny access by default. Record the authenticated principal and the requested resource.'

def call(name, **args):
    return {'role': 'assistant', 'tool_calls': [{'id': name, 'type': 'function', 'function': {'name': name, 'arguments': json.dumps(args)}}]}

class Fake:
    model = 'fixture-model'
    def __init__(self, responses, missing=None):
        self.responses = iter(responses); self.actions = []; self._missing = missing or []
    def get(self, key, default=''): return default
    def missing(self): return self._missing
    def excluded(self, url): return False
    async def completion(self, messages, tools, max_tokens):
        self.actions.append('model')
        return next(self.responses), {'total_tokens': 50}
    async def search(self, query):
        self.actions.append(('search',query))
        return [{'url': 'https://example.org/access', 'title': 'Access controls', 'content': PASSAGE}]
    async def extract(self, urls):
        self.actions.append(('read',urls))
        return [{'url': urls[0], 'raw_content': PASSAGE}], []

def finish(claims=None, scenario='idor_basket_access'):
    return call('finish', summary='Assessment of access-control evidence.', stop_reason='Sufficient evidence for a bounded demonstration.',
        claims=claims or [{'text':'Enforce authorization on each request.', 'kind':'source_supported_fact', 'source_id':'S1', 'quote':PASSAGE.split('. ')[0]+'.'}],
        scenario_id=scenario, scenario_reason='Use two synthetic accounts to test an ownership boundary.')

def execute(fake, limits=None, question='Assess access-control evidence.'):
    saved=[];r={'id':'a'*24, 'question':question}
    asyncio.run(Research(fake,r,lambda r:saved.append(copy.deepcopy(r)),limits).run())
    return r,saved

def test_model_selects_tools_and_stops_without_forced_followup():
    f=Fake([call('plan',summary='Read access-control guidance.'), call('search',query='authorization checks',purpose='Find authoritative guidance.'),
        call('read',source_ids=['S1'],purpose='Read supporting text.'), finish(),call('assess_support',supported=[0])])
    r,saved=execute(f)
    assert r['status']=='completed'
    assert r['report']['claims'][0]['support']=='quote_matched_model_checked'
    assert [a for a in f.actions if isinstance(a,tuple)]==[('search','authorization checks'),('read',['https://example.org/access'])]
    assert [e['seq'] for e in r['events']]==list(range(1,len(r['events'])+1))
    started=next(s for s in saved if s['events'][-1]['type']=='search_started')
    assert started['sources']==[]  # event persisted before tool completed
    assert r['sources'][0]['extracted']

def test_model_can_choose_followup_and_uncertainty():
    f=Fake([call('search',query='first',purpose='Initial evidence'),call('search',query='contradictory guidance',purpose='Resolve disagreement'),finish()])
    r,_=execute(f)
    assert r['usage']['searches']==2
    assert r['status']=='incomplete'  # snippets are not extracted support
    assert r['report']['claims'][0]['kind']=='unresolved_question'

def test_quote_matching_is_not_enough_without_entailment():
    claims=[{'text':'This fixes every vulnerability.', 'kind':'source_supported_fact','source_id':'S1','quote':PASSAGE}]
    f=Fake([call('search',query='access',purpose='evidence'),call('read',source_ids=['S1'],purpose='read'),finish(claims),call('assess_support',supported=[])])
    r,_=execute(f)
    assert r['status']=='incomplete'
    assert r['report']['claims'][0]['support']=='unverified'

def test_missing_provider_no_fabricated_calls():
    f=Fake([],missing=['NEBIUS_API_KEY'])
    r,_=execute(f)
    assert r['status']=='unavailable' and not f.actions and r['report'] is None
    assert 'NEBIUS_API_KEY' in r['events'][-1]['reason']

def test_search_and_iteration_budgets():
    f=Fake([call('search',query='one',purpose='gap'),call('search',query='two',purpose='gap')])
    r,_=execute(f,Limits(iterations=2,searches=1))
    assert r['usage']['searches']==1 and r['status']=='budget_exhausted'

def test_token_budget_prevents_request():
    f=Fake([]);r,_=execute(f,Limits(tokens=1))
    assert f.actions==[] and r['status']=='unavailable'

def test_timeout_and_cancellation_preserve_events():
    class Slow(Fake):
        async def completion(self,*args): await asyncio.sleep(60)
    r,_=execute(Slow([]),Limits(seconds=.01))
    assert r['status']=='budget_exhausted' and r['events'][-1]['type']=='stopped'
    async def cancel():
        r={'id':'a'*24,'question':'test question'}
        task=asyncio.create_task(Research(Slow([]),r,lambda r:None).run())
        await asyncio.sleep(.01);task.cancel();await task
        return r
    assert asyncio.run(cancel())['status']=='cancelled'

def test_cve_cannot_propose_generic_lab():
    f=Fake([finish()]);r,_=execute(f,question='Investigate CVE-2025-12345')
    assert r['report']['scenario_id']==''

@pytest.mark.parametrize('url',['http://127.0.0.1/a','http://169.254.169.254/','file:///etc/passwd','https://user:password@example.org/','http://localhost/','http://[::1]/','https://example.org:9000/'])
def test_private_or_credential_urls_rejected(url):
    with pytest.raises(ProviderError):public_url(url)

def test_provider_errors_never_echo_body_or_key():
    key='fake-credential-never-publish'
    p=Providers(lambda k,d='':key if k=='NEBIUS_API_KEY' else d, httpx.MockTransport(lambda r:httpx.Response(401,text=key)))
    with pytest.raises(ProviderError) as e:asyncio.run(p.models())
    assert key not in str(e.value)

def test_redirect_or_bad_provider_base_rejected():
    p=Providers(lambda k,d='':'key' if k=='NEBIUS_API_KEY' else 'https://example.org' if k=='NEBIUS_TOKEN_FACTORY_BASE_URL' else d)
    with pytest.raises(ProviderError):asyncio.run(p.models())

def test_extraction_exclusions_and_no_arbitrary_pages():
    p=Providers(lambda k,d='':'key' if k=='TAVILY_API_KEY' else d)
    with pytest.raises(ProviderError):asyncio.run(p.extract(['https://pwning.owasp-juice.shop/guide']))
    f=Fake([call('read',source_ids=['made-up'],purpose='read'),finish()]);r,_=execute(f)
    assert r['usage']['reads']==0

def test_router_persists_unavailable_and_guards_lab(tmp_path):
    runs=Runs(tmp_path,lambda:Fake([],missing=['TAVILY_API_KEY']))
    app=FastAPI();app.include_router(router_for(runs))
    with TestClient(app) as client:
        r=client.post('/research/runs',json={'question':'Assess broken access control'}).json()
        # Give the background task an event-loop turn.
        actual=client.get('/research/runs/'+r['id']).json()
        assert actual['status']=='unavailable'
        assert client.post('/research/runs/'+r['id']+'/lab').status_code==409
        assert client.get('/research/runs/not-a-run').status_code==404
        assert (tmp_path/(r['id']+'.json')).exists()

def test_restart_marks_inflight_run_interrupted(tmp_path):
    r={'id':'b'*24,'status':'running','events':[]}
    old=Runs(tmp_path);old.save(r)
    restored=Runs(tmp_path).get(r['id'])
    assert restored['status']=='interrupted'

def test_standalone_refuses_remote_or_cross_site():
    from redbears_research.app import app
    with TestClient(app,base_url='http://localhost') as c:
        assert c.get('/').status_code==200
        assert c.get('/',headers={'host':'attacker.example'}).status_code==403
        assert c.post('/research/runs',headers={'origin':'https://evil.example'},json={'question':'hello there'}).status_code==403


def test_three_material_claims_have_exact_supporting_passages():
    quotes=['Authorization must be enforced on every request.', 'Deny access by default.', 'Record the authenticated principal and the requested resource.']
    claims=[{'text':q,'kind':'source_supported_fact','source_id':'S1','quote':q} for q in quotes]
    f=Fake([call('search',query='authorization',purpose='evidence'),call('read',source_ids=['S1'],purpose='read'),finish(claims),call('assess_support',supported=[0,1,2])])
    r,_=execute(f)
    assert len(r['report']['claims'])==3
    for c in r['report']['claims']:
        assert c['quote'] in r['sources'][0]['passage']
        assert c['support']=='quote_matched_model_checked'


def test_credential_redaction_does_not_break_json_events():
    r={'id':'a'*24,'question':'test'}
    engine=Research(Fake([]),r,lambda r:None)
    engine.event('tool_error',detail='Bearer fixture-secret-token')
    assert r['events'][0]['detail']=='[redacted]'


def test_model_cannot_invoke_arbitrary_execution_tool():
    f=Fake([call('shell',command='read private files'),finish()])
    r,_=execute(f)
    assert not any(isinstance(a,tuple) for a in f.actions)
    assert r['status']=='incomplete'
