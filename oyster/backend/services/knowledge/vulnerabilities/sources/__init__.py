"""One acquisition/normalization module per approved vulnerability source:
``kev``, ``nvd``, ``epss``, ``cwe``, ``capec``. Each fetches raw upstream data
and normalizes it into the dataclasses in ``..models`` — no storage, no
embedding, no execution happens in this package."""
