"""Credential-isolated HTTP clients. Provider bodies/errors are never logged."""
from __future__ import annotations
import ipaddress
import os
from urllib.parse import urlsplit, urlunsplit
import httpx


class ProviderError(Exception):
    pass


def public_url(value: str) -> str:
    try:
        u = urlsplit(value)
        host = (u.hostname or '').lower()
        if u.scheme not in ('http', 'https') or not host or u.username or u.password or u.port not in (None, 80, 443):
            raise ValueError()
        if host == 'localhost' or host.endswith(('.local', '.internal', '.localhost')) or '.' not in host:
            raise ValueError()
        try:
            if not ipaddress.ip_address(host).is_global:
                raise ValueError()
        except ValueError:
            # A literal address must pass the global-address test.
            if ':' in host or all(c.isdigit() or c == '.' for c in host):
                raise ValueError()
        # Do not retain credentials embedded in URL query/fragment parameters.
        return urlunsplit((u.scheme, u.netloc, u.path, '', ''))
    except (TypeError, ValueError):
        raise ProviderError('Only public HTTP(S) source URLs without credentials are accepted.') from None


class Providers:
    def __init__(self, settings=None, transport=None):
        self.get = settings or (lambda k, default='': os.environ.get(k, default))
        self.transport = transport

    @property
    def model(self):
        return self.get('NEMOTRON_REASONING_MODEL', '')

    def missing(self):
        return [k for k in ('NEBIUS_API_KEY', 'TAVILY_API_KEY', 'NEMOTRON_REASONING_MODEL') if not self.get(k, '')]

    async def request(self, provider, path, body=None):
        if provider == 'nebius':
            key = self.get('NEBIUS_API_KEY', '')
            base = self.get('NEBIUS_TOKEN_FACTORY_BASE_URL', 'https://api.tokenfactory.nebius.com/v1').rstrip('/')
            allowed = 'api.tokenfactory.nebius.com'
        else:
            key = self.get('TAVILY_API_KEY', '')
            base = 'https://api.tavily.com'
            allowed = 'api.tavily.com'
        if not key:
            raise ProviderError(f'{provider}: credential is not configured.')
        u = urlsplit(base)
        if u.scheme != 'https' or u.hostname != allowed or u.username or u.password or u.port not in (None, 443):
            raise ProviderError(f'{provider}: unsupported provider endpoint.')
        try:
            async with httpx.AsyncClient(timeout=30, follow_redirects=False, transport=self.transport) as client:
                response = await client.request('POST' if body is not None else 'GET', base + path,
                                                headers={'Authorization': f'Bearer {key}'}, json=body)
            if response.status_code != 200:
                raise ProviderError(f'{provider}: HTTP {response.status_code}; check credentials, quota and provider status.')
            return response.json()
        except ProviderError:
            raise
        except Exception:
            raise ProviderError(f'{provider}: request failed or returned invalid data.') from None

    async def models(self):
        data = await self.request('nebius', '/models')
        return [m['id'] for m in data.get('data', []) if isinstance(m.get('id'), str)]

    async def completion(self, messages, tools, max_tokens):
        if not self.model:
            raise ProviderError('NEMOTRON_REASONING_MODEL is not configured; choose an account catalog model.')
        data = await self.request('nebius', '/chat/completions', {
            'model': self.model, 'messages': messages, 'tools': tools,
            'tool_choice': 'auto', 'max_tokens': max_tokens, 'temperature': 0.2,
        })
        try:
            message = data['choices'][0]['message']
            # Strip any provider-specific hidden reasoning fields before reuse.
            return {k: message[k] for k in ('role', 'content', 'tool_calls') if k in message}, data.get('usage', {})
        except (KeyError, IndexError, TypeError):
            raise ProviderError('Token Factory returned no usable completion.') from None

    def excluded(self, url):
        host = (urlsplit(url).hostname or '').lower()
        raw = self.get('TAVILY_EXCLUDE_DOMAINS', 'pwning.owasp-juice.shop,help.owasp-juice.shop')
        domains = raw.split(',') if isinstance(raw, str) else raw
        return any(host == d.strip() or host.endswith('.' + d.strip()) for d in domains if d.strip())

    async def search(self, query):
        raw = self.get('TAVILY_EXCLUDE_DOMAINS', 'pwning.owasp-juice.shop,help.owasp-juice.shop')
        domains = raw.split(',') if isinstance(raw, str) else list(raw)
        data = await self.request('tavily', '/search', {'query': query, 'max_results': 5,
            'search_depth': 'advanced', 'exclude_domains': domains, 'include_raw_content': False})
        return data.get('results', [])[:5]

    async def extract(self, urls):
        urls = [public_url(u) for u in urls]
        if any(self.excluded(u) for u in urls):
            raise ProviderError('Extraction blocked by research source exclusions.')
        data = await self.request('tavily', '/extract', {'urls': urls[:3], 'extract_depth': 'basic', 'format': 'markdown'})
        return data.get('results', []), data.get('failed_results', [])
