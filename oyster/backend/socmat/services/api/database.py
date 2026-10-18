"""Per-owner SQLite isolation for the SOC Copilot workbench.

Oyster is multi-user (private per-account projects). socmat was single-tenant,
so mounting its API as-is would let one account read another's cases. Rather
than thread an ``owner_id`` column through all 27 routers and 24 models, we
isolate at the one shared entry point every router already uses — ``get_db`` —
by giving each Oyster account its OWN SQLite database file. The owner id is the
caller's immutable Supabase ``sub`` (``dev-local`` when auth is disabled), set
on ``request.state.socmat_owner`` by the mount middleware in main.py.

A brand-new owner DB gets its schema created and its reference playbook
templates seeded on first use. Everything downstream is unchanged.
"""

import os
import re
import threading
from pathlib import Path

from fastapi import Request
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

# Absolute, CWD-independent base dir for the per-owner databases. Overridable
# via SOCMAT_DB_DIR. parents[2] == the socmat/ package root.
_DB_DIR = (
    Path(os.getenv("SOCMAT_DB_DIR"))
    if os.getenv("SOCMAT_DB_DIR")
    else Path(__file__).resolve().parents[2] / "data" / "userdbs"
)


class Base(DeclarativeBase):
    pass


_factories: dict[str, sessionmaker] = {}
_factories_lock = threading.Lock()


def _safe_owner(owner_id: str | None) -> str:
    """Supabase ``sub`` UUIDs / ``dev-local`` → a filesystem-safe stem."""
    stem = re.sub(r"[^A-Za-z0-9_.-]", "_", (owner_id or "default").strip())
    return stem or "default"


def session_factory_for(owner_id: str | None) -> sessionmaker:
    """Return (creating if needed) the sessionmaker bound to this owner's DB.
    First creation stamps the schema and seeds reference playbook templates."""
    key = _safe_owner(owner_id)
    with _factories_lock:
        existing = _factories.get(key)
        if existing is not None:
            return existing
        _DB_DIR.mkdir(parents=True, exist_ok=True)
        engine = create_engine(
            f"sqlite:///{_DB_DIR / f'{key}.db'}",
            connect_args={"check_same_thread": False},
        )
        factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        import socmat.services.api.models  # noqa: F401 — register all models first
        Base.metadata.create_all(bind=engine)
        try:
            from socmat.services.api.playbook_seeds import seed_playbook_templates
            seed_playbook_templates(factory)
        except Exception:
            pass  # seeding is best-effort; never block DB availability
        _factories[key] = factory
        return factory


# Module-level default factory — back-compat for any caller that still imports
# SessionLocal directly (the playbook seeder), and for init_db() at startup.
SessionLocal = session_factory_for("default")


def get_db(request: Request):
    """Yield a session bound to the CALLER's isolated database."""
    owner = getattr(request.state, "socmat_owner", None)
    db = session_factory_for(owner)()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Ensure the default owner DB exists (per-owner DBs are created lazily)."""
    session_factory_for("default")
