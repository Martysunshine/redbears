"""FIRST EPSS — daily bulk CSV snapshot (score + percentile per CVE).

https://www.first.org/epss/
"""

from __future__ import annotations

import csv
import gzip
import io
import re

import httpx

import config

from .. import identity
from ..models import EpssEntry
from ..rate_limit import get_capped

SOURCE_ID = "first-epss"
LICENCE = "epss-first-terms"
ATTRIBUTION = "Exploit Prediction Scoring System (EPSS), FIRST.org, Inc."

_HEADER_RE = re.compile(r"score_date:([0-9T:\-Z]+)")


async def fetch_raw() -> bytes:
    async with httpx.AsyncClient(timeout=config.DATASET_NET_TIMEOUT, follow_redirects=True) as client:
        return await get_capped(client, config.EPSS_BULK_URL)


def normalize(raw_gz: bytes) -> tuple[list[EpssEntry], str]:
    """Returns (entries, score_date)."""
    text = gzip.decompress(raw_gz).decode("utf-8", errors="replace")
    lines = text.splitlines()
    if not lines:
        return [], ""
    m = _HEADER_RE.search(lines[0])
    score_date = m.group(1) if m else ""
    reader = csv.DictReader(lines[1:])
    entries: list[EpssEntry] = []
    for row in reader:
        cve_id = identity.normalize_cve(row.get("cve"))
        if cve_id is None:
            continue
        try:
            score = float(row["epss"])
            percentile = float(row["percentile"])
        except (KeyError, ValueError, TypeError):
            continue
        if not (0.0 <= score <= 1.0 and 0.0 <= percentile <= 1.0):
            continue  # never store an out-of-range "probability"
        entries.append(EpssEntry(cve_id=cve_id, score=score, percentile=percentile, as_of=score_date))
    return entries, score_date
