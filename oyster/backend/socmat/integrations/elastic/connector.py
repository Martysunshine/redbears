"""
Optional live Elasticsearch REST API connector.

Credentials are read exclusively from environment variables — never hardcoded.

Environment variables:
  ELASTIC_URL        — e.g. https://my-cluster.es.io:9243
  ELASTIC_API_KEY    — Elasticsearch API key (base64-encoded value from Kibana console)
  ELASTIC_VERIFY_SSL — "true" (default) or "false" to skip cert verification

WARNING: Do not use production credentials in development or demo environments.
         Only read queries are sent. No data is written to Elasticsearch.
"""

import logging
import os
from urllib.parse import urlparse

import requests

_log = logging.getLogger("socmat.elastic")

# Text in the "error" field is rendered in the analyst's browser. It must not
# name environment variables (an operator instruction that also maps our
# configuration for a caller), the full cluster URL, or a requests exception's
# own words. Those go to the log.
NOT_CONFIGURED = "Elasticsearch connector is not configured on this server."
AUTH_FAILED = "Authentication failed. Check the connector's credentials."
UNEXPECTED = "Unexpected error talking to Elasticsearch. See the server log."


def _host(url: str) -> str:
    try:
        return urlparse(url).hostname or "the Elasticsearch host"
    except Exception:  # noqa: BLE001
        return "the Elasticsearch host"


SAFETY_WARNING = (
    "WARNING: This connector queries a live Elasticsearch instance. "
    "Do not use production credentials in development or demo environments. "
    "Only read queries are sent. No data is written to Elasticsearch."
)


def _get_config() -> tuple:
    """Return (url, api_key, verify_ssl). url/api_key are None if not set."""
    url = os.environ.get("ELASTIC_URL", "").strip().rstrip("/")
    api_key = os.environ.get("ELASTIC_API_KEY", "").strip()
    verify_ssl_str = os.environ.get("ELASTIC_VERIFY_SSL", "true").strip().lower()
    verify_ssl = verify_ssl_str not in ("false", "0", "no")
    return (url or None, api_key or None, verify_ssl)


def is_configured() -> bool:
    """Return True if ELASTIC_URL and ELASTIC_API_KEY are both set."""
    url, api_key, _ = _get_config()
    return bool(url and api_key)


def _auth_headers(api_key: str) -> dict:
    return {
        "Authorization": f"ApiKey {api_key}",
        "Content-Type": "application/json",
    }


def test_connection() -> dict:
    """
    Test the Elasticsearch REST API connection via GET / (root info endpoint).
    Uses the root endpoint instead of /_cluster/health so that read-only API
    keys without cluster monitor privileges can still verify connectivity.
    Returns: {configured, connected, cluster_info, error, warning}.
    """
    url, api_key, verify = _get_config()
    if not url or not api_key:
        return {
            "configured": False,
            "connected": False,
            "cluster_info": None,
            "error": NOT_CONFIGURED,
            "warning": SAFETY_WARNING,
        }
    try:
        resp = requests.get(
            f"{url}/",
            headers=_auth_headers(api_key),
            timeout=10,
            verify=verify,
        )
        if resp.status_code == 401:
            return {
                "configured": True,
                "connected": False,
                "cluster_info": None,
                "error": AUTH_FAILED,
                "warning": SAFETY_WARNING,
            }
        resp.raise_for_status()
        data = resp.json()
        cluster_info = {
            "cluster_name": data.get("cluster_name", "unknown"),
            "version": data.get("version", {}).get("number", "unknown"),
            "tagline": data.get("tagline", ""),
        }
        return {
            "configured": True,
            "connected": True,
            "cluster_info": cluster_info,
            "error": None,
            "warning": SAFETY_WARNING,
        }
    except requests.exceptions.ConnectionError:
        return {
            "configured": True,
            "connected": False,
            "cluster_info": None,
            "error": f"Could not connect to {_host(url)}.",
            "warning": SAFETY_WARNING,
        }
    except requests.exceptions.Timeout:
        return {
            "configured": True,
            "connected": False,
            "cluster_info": None,
            "error": "Connection timed out (10 s).",
            "warning": SAFETY_WARNING,
        }
    except Exception as exc:  # noqa: BLE001
        _log.warning("elastic test_connection failed: %s", exc)
        return {
            "configured": True,
            "connected": False,
            "cluster_info": None,
            "error": UNEXPECTED,
            "warning": SAFETY_WARNING,
        }


def run_esql_search(esql_query: str, max_results: int = 50) -> dict:
    """
    Run an ES|QL query against the live Elasticsearch instance via POST /_query.
    Requires Elasticsearch 8.11+. Results are capped at 500.

    Automatically appends '| LIMIT N' if the query has no LIMIT clause.
    Returns: {result_count, results, error, warning}.
    Results are a list of dicts keyed by column name.
    """
    url, api_key, verify = _get_config()
    if not url or not api_key:
        return {
            "result_count": 0,
            "results": [],
            "error": NOT_CONFIGURED,
            "warning": SAFETY_WARNING,
        }

    max_results = min(max(1, max_results), 500)

    query = esql_query.strip()
    q_upper = query.upper()
    if "| LIMIT " not in q_upper:
        query = f"{query}\n| LIMIT {max_results}"

    try:
        resp = requests.post(
            f"{url}/_query",
            headers=_auth_headers(api_key),
            json={"query": query},
            timeout=30,
            verify=verify,
        )
        if resp.status_code == 401:
            return {
                "result_count": 0, "results": [],
                "error": AUTH_FAILED,
                "warning": SAFETY_WARNING,
            }
        if resp.status_code == 400:
            # The cluster's "reason" describes the analyst's own query and is
            # worth showing; the raw response body is not.
            try:
                err_body = resp.json()
                err_msg = err_body.get("error", {}).get("reason") or "the query was rejected"
            except Exception:  # noqa: BLE001
                err_msg = "the query was rejected"
            return {
                "result_count": 0, "results": [],
                "error": f"ES|QL query error: {err_msg}",
                "warning": SAFETY_WARNING,
            }
        resp.raise_for_status()
        data = resp.json()
        columns = [col["name"] for col in data.get("columns", [])]
        values = data.get("values", [])
        results = [dict(zip(columns, row)) for row in values]
        return {
            "result_count": len(results),
            "results": results,
            "error": None,
            "warning": SAFETY_WARNING,
        }
    except requests.exceptions.ConnectionError:
        return {
            "result_count": 0, "results": [],
            "error": f"Could not connect to {_host(url)}.",
            "warning": SAFETY_WARNING,
        }
    except requests.exceptions.Timeout:
        return {
            "result_count": 0, "results": [],
            "error": "Request timed out.",
            "warning": SAFETY_WARNING,
        }
    except Exception as exc:  # noqa: BLE001
        _log.warning("elastic run_esql_search failed: %s", exc)
        return {
            "result_count": 0, "results": [],
            "error": UNEXPECTED,
            "warning": SAFETY_WARNING,
        }
