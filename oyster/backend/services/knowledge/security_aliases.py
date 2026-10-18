"""Reviewable security alias/acronym table (2026-09-15 accuracy cycle).

Retrieval is untrusted-text-in, ranked-results-out — this module only expands
a QUERY's search text with equivalent terms before it reaches the vector and
lexical channels. It never writes into the knowledge store, never alters a
stored chunk, and never hard-codes an evaluation case's expected answer:
every entry here is a genuine, verifiable term equivalence a security
practitioner would recognize, independent of any specific eval query.

Two kinds of entries:

* ``ALIASES`` — acronym/full-name pairs (e.g. "AD" <-> "Active Directory").
  Diagnostic evidence: queries naming a Microsoft-identity acronym (e.g.
  "Entra") were losing to topically-adjacent-but-wrong packs (generic Azure /
  AD content) because the corpus text and the query didn't share enough exact
  terms for the lexical channel to compete with vector's broad semantic pull.
* ``NAMED_VULNERABILITIES`` — well-known public nicknames for a specific CVE
  (e.g. "Log4Shell" -> "CVE-2021-44228"). Diagnostic evidence: a query that
  names a vulnerability by its famous nickname instead of its CVE id never
  triggers retrieval.py's existing exact-CVE-id boost at all, because
  ``vulnerabilities.identity.find_identifiers`` only recognizes CVE-shaped
  tokens — it has no idea "Log4Shell" and "CVE-2021-44228" are the same
  vulnerability. Expanding the query text with the real id lets that
  existing, already-tested boost mechanism fire.

Both tables are intentionally small and named-example-only, not an attempt at
an exhaustive security dictionary — add an entry only when it is a real,
independently-verifiable equivalence, never to make one specific eval case
pass.
"""

from __future__ import annotations

import re

# acronym/short form -> one or more full/equivalent forms. Matching is
# case-insensitive whole-word (so "AD" doesn't fire inside "add" or "ADFS").
ALIASES: dict[str, tuple[str, ...]] = {
    "pth": ("pass the hash",),
    "ad": ("active directory",),
    "entra": ("entra id", "azure ad", "azure active directory"),
    "entra id": ("azure ad", "azure active directory"),
    "azure ad": ("entra id", "azure active directory"),
    "oidc": ("openid connect",),
    "openid connect": ("oidc",),
    "tgt": ("ticket-granting ticket", "ticket granting ticket"),
    "mfa": ("multi-factor authentication", "multifactor authentication"),
    "dcsync": ("directory replication service", "drs"),
    "kerberoast": ("kerberoasting",),
}

# well-known public nickname -> canonical CVE id(s). Each entry here is a
# widely-documented, unambiguous 1:1 (or small 1:few) mapping, not a guess.
NAMED_VULNERABILITIES: dict[str, tuple[str, ...]] = {
    "log4shell": ("CVE-2021-44228",),
    "eternalblue": ("CVE-2017-0144",),
    "heartbleed": ("CVE-2014-0160",),
    "shellshock": ("CVE-2014-6271",),
    "printnightmare": ("CVE-2021-34527",),
    "zerologon": ("CVE-2020-1472",),
    "bluekeep": ("CVE-2019-0708",),
    "spring4shell": ("CVE-2022-22965",),
}

_WORD_RE = re.compile(r"[a-z0-9][a-z0-9\-]*")


def expand_query(query: str) -> str:
    """Return the query with recognized aliases/nicknames appended (never
    replacing the original text, so existing behavior for every
    non-matching query is byte-for-byte unchanged). Bounded and
    deterministic: at most a handful of extra terms, no external lookup."""
    if not query:
        return query
    lower = query.lower()
    words = _WORD_RE.findall(lower)
    word_set = set(words)
    extra: list[str] = []

    for key, expansions in ALIASES.items():
        if " " in key:
            if key in lower and key not in extra:
                extra.extend(e for e in expansions if e not in extra)
        elif key in word_set:
            extra.extend(e for e in expansions if e not in extra)

    for nickname, cve_ids in NAMED_VULNERABILITIES.items():
        if nickname in word_set:
            extra.extend(c for c in cve_ids if c not in extra)

    if not extra:
        return query
    return f"{query} ({' '.join(extra)})"
