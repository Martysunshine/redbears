"""Connector data model + abstract base class.

Nothing here performs I/O or executes anything — these are pure declarations and
an interface. Concrete connectors (git / stix / archive / local) implement
:meth:`SourceConnector.acquire` and :meth:`SourceConnector.normalize`.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict


class LicenceDisposition:
    """How a licence permits us to handle a source's content."""

    STORE_LOCAL = "store_local"          # full text may be stored + indexed locally
    METADATA_ONLY = "metadata_only"      # only titles/paths/links may be stored
    LINK_ONLY = "link_only"              # reference by URL only
    EVALUATION_ONLY = "evaluation_only"  # datasets usable only for eval, never stored as knowledge
    MANUAL_CONFIRM = "manual_confirm"    # requires explicit human confirmation first
    EXCLUDED = "excluded"                # must not be ingested at all

    ALL = (STORE_LOCAL, METADATA_ONLY, LINK_ONLY, EVALUATION_ONLY,
           MANUAL_CONFIRM, EXCLUDED)


class SourceType:
    GIT = "git"
    JSON_STIX = "json_stix"
    ARCHIVE = "archive"
    API = "api"
    LOCAL = "local"
    PDF = "pdf"
    RFC = "rfc"


@dataclass
class ConnectorProfile:
    """The complete, declarative definition of one approved source.

    Every field a reviewer needs to reason about provenance, licensing, risk and
    acquisition lives here. Missing licence/attribution blocks installation.
    """

    # Identity
    id: str
    name: str
    display_name: str
    source_type: str                      # SourceType.*

    # Upstream location + acquisition allow-list
    upstream_url: str                     # canonical human landing page
    repo_url: str | None = None           # git remote / archive / api base
    default_ref: str = "master"           # branch/tag/release to pin to
    allowed_hosts: tuple[str, ...] = ()    # hostnames this connector may contact

    # Licence + attribution (installation is blocked if licence is missing)
    licence: str | None = None
    licence_disposition: str = LicenceDisposition.STORE_LOCAL
    attribution: str | None = None
    requires_attribution: bool = True

    # Selection rules
    include_globs: tuple[str, ...] = ("**/*.md",)
    exclude_globs: tuple[str, ...] = ()
    file_types: tuple[str, ...] = (".md",)

    # Normalization / chunking
    chunk_strategy: str = "markdown_section"
    blob_url_template: str | None = None  # e.g. "{repo}/blob/{ref}/{path}"

    # Taxonomy + classification
    domain: str = "general"               # coarse offensive/defensive/etc.
    security_domain: str = "general"      # fine-grained taxonomy slug
    tags: tuple[str, ...] = ()
    authority: str | None = None
    publisher: str | None = None
    trust_level: str = "community"        # official | authoritative | community | unverified
    risk_classification: str = "informational"
    active_execution_possible: bool = False
    applicable_tools: tuple[str, ...] = ()
    applicable_platforms: tuple[str, ...] = ()

    # Freshness
    freshness_policy: str | None = None

    # Resource limits (fall back to config defaults when None)
    max_files: int | None = None
    max_file_bytes: int | None = None

    # Materialized pack id (defaults to the connector id)
    pack_id: str | None = None

    def resolved_pack_id(self) -> str:
        return self.pack_id or self.id

    def to_dict(self) -> dict:
        d = asdict(self)
        d["pack_id"] = self.resolved_pack_id()
        return d


@dataclass
class NormalizedDoc:
    """One normalized, provenance-tagged document ready to be materialized.

    ``content`` is the cleaned (bidi/zero-width-stripped) text. ``injection``
    holds any prompt-injection findings detected in the raw source so the import
    can be flagged/audited (content is still stored as inert data)."""

    rel_path: str                 # path within the materialized pack (stable id input)
    title: str
    section: str
    heading_path: tuple[str, ...]
    content: str
    source_url: str | None = None
    source_path: str | None = None   # original path in the upstream
    injection: list = field(default_factory=list)

    def content_checksum(self) -> str:
        return hashlib.sha256(self.content.encode("utf-8")).hexdigest()


class SourceConnector:
    """Abstract connector. Concrete subclasses implement acquire + normalize."""

    def __init__(self, profile: ConnectorProfile):
        self.profile = profile

    # --- capability / health -------------------------------------------------
    def health(self) -> dict:
        """Report whether this connector can run in the current environment
        (binaries present, etc.). Never raises."""
        return {"available": True, "reason": None}

    def discover_version(self) -> str | None:
        """Return the upstream version/commit *without* a full acquisition, or
        None if it cannot be determined offline. Must never raise."""
        return None

    # --- acquisition + normalization (implemented by subclasses) -------------
    def acquire(self, workdir):
        """Fetch the source into ``workdir``. Returns an opaque handle
        (e.g. resolved commit SHA). Raises on failure."""
        raise NotImplementedError

    def normalize(self, acquired, workdir) -> list[NormalizedDoc]:
        """Turn the acquired source into normalized, provenance-tagged docs."""
        raise NotImplementedError
