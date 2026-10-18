"""Optional cookbook smoke run before live integration. Python 3.12+ recommended.
Uses the cookbook framework pattern, with the project's existing variable names.
"""
import os
import sys
from dotenv import load_dotenv

def main():
    load_dotenv(override=False)
    required=('NEBIUS_API_KEY','TAVILY_API_KEY','NEMOTRON_REASONING_MODEL')
    if any(not os.getenv(k) for k in required):
        print('BLOCKED: configure the two provider keys locally and verify the account model ID first.')
        return 2
    from deepagents import create_deep_agent
    from langchain_nebius import ChatNebius
    from langchain_tavily import TavilySearch
    model=ChatNebius(model=os.environ['NEMOTRON_REASONING_MODEL'],base_url=os.getenv('NEBIUS_TOKEN_FACTORY_BASE_URL','https://api.tokenfactory.nebius.com/v1'),max_tokens=1800,timeout=30,max_retries=0)
    search=TavilySearch(max_results=5,search_depth='advanced')
    agent=create_deep_agent(model=model,tools=[search])
    result=agent.invoke({'messages':[{'role':'user','content':sys.argv[1] if len(sys.argv)>1 else 'Research defensive access control checks; cite your evidence.'}]},config={'recursion_limit':20})
    print('Deep research report:')
    print(result['messages'][-1].content)
    return 0

if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception:print('Cookbook run failed; inspect local configuration and dependency compatibility. No provider body logged.');raise SystemExit(1)
