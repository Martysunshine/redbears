"""Source Connector framework for the Knowledge Service.

A *connector* turns an explicitly-approved upstream source (a git repository, a
structured JSON/STIX feed, an official archive, an API, or a local import) into a
normalized, provenance-rich, licence-validated **Knowledge Pack** on disk, which
then flows through the existing verified ``pack_service`` install pipeline
(chunk → embed → SQLite provenance → citation → atomic install → history).

Design rules (non-negotiable):

* Every source is a declared :class:`ConnectorProfile`. There is **no**
  unrestricted web scraper — a connector can only touch its own allowed
  upstream.
* Imported content is **untrusted DATA**. It is prompt-injection scanned and
  bidi/zero-width-neutralized on the way in, and it can never execute, invoke a
  tool, change policy/scope, or approve anything.
* Installation is **blocked** when required licence or provenance metadata is
  missing, or when the licence disposition forbids local storage.
* A failed import leaves the currently-installed pack untouched (atomic
  directory swap).
"""

from .base import (ConnectorProfile, LicenceDisposition, NormalizedDoc,
                   SourceConnector)

__all__ = [
    "ConnectorProfile",
    "LicenceDisposition",
    "NormalizedDoc",
    "SourceConnector",
]
