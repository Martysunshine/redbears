"""Modular third-party integration adapters (Nemotron reasoning, Tavily, Devin).

See base.py for the shared contract. Each provider's adapter lives in its own
module and owns its own request/response schema. ``registry`` exposes the
singleton instances used by routers/integrations.py and the investigation
workflow.
"""
