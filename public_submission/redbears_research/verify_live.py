"""Explicit, bounded live account smoke check. Prints no credentials or provider bodies."""
import asyncio
import json
import os
from dotenv import load_dotenv
from .providers import Providers, ProviderError
from .engine import tool

async def main():
    load_dotenv(override=False)
    p=Providers()
    if not os.getenv('NEBIUS_API_KEY') or not os.getenv('TAVILY_API_KEY'):
        print('BLOCKED: configure NEBIUS_API_KEY and TAVILY_API_KEY locally; never paste keys in chat.')
        return 2
    ids=await p.models()
    selected=p.model
    if selected and selected not in ids:
        raise ProviderError('Configured model is not in the account catalog.')
    candidates=[selected] if selected else [m for m in ids if 'nemotron' in m.lower() and not any(x in m.lower() for x in ('embed','rerank'))]
    candidates=candidates[:3]
    fallback=[m for m in ids if any(x in m.lower() for x in ('qwen','minimax','llama','deepseek')) and not any(x in m.lower() for x in ('embed','rerank'))][:3]
    if not candidates: print('No Nemotron candidate in the account catalog; testing catalog fallback models.')
    schema=[tool('record_check','Record the verification marker.',{'marker':{'type':'string'}},['marker'])]
    verified=None
    for model in (candidates+fallback)[:6]:
        os.environ['NEMOTRON_REASONING_MODEL']=model
        try:
            msg,_=await p.completion([{'role':'user','content':'Call record_check with marker redbears-ready. Do not answer in prose.'}],schema,256)
            calls=msg.get('tool_calls',[])
            if calls and calls[0]['function']['name']=='record_check' and json.loads(calls[0]['function']['arguments']).get('marker')=='redbears-ready':
                verified=model;break
        except (ProviderError,KeyError,ValueError): pass
    if not verified: raise ProviderError('No tested catalog model completed the tool-call smoke check.')
    if 'nemotron' not in verified.lower():
        print('Using an explicitly verified Token Factory fallback; no Nemotron tool-call success was established.')
    print('Verified Token Factory tool-calling model:',verified)
    print('Set NEMOTRON_REASONING_MODEL to that exact ID in the local configuration.')
    rows=await p.search('OWASP authorization deny by default validate permissions every request')
    urls=[r['url'] for r in rows if r.get('url') and not p.excluded(r['url'])][:1]
    if not urls:raise ProviderError('Tavily search returned no usable sources.')
    extracted,failed=await p.extract(urls)
    if not any(r.get('raw_content') for r in extracted):raise ProviderError('Tavily extraction returned no page text.')
    print('Live Tavily search and extraction passed.')
    return 0

if __name__=='__main__':
    try:raise SystemExit(asyncio.run(main()))
    except ProviderError as exc:print(str(exc));raise SystemExit(1)
