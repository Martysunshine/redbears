"""Offline check for account deletion. RUN DIRECTLY, not via pytest:

    cd oyster/backend && python tests/standalone_account_deletion_check.py

Deliberately NOT named test_*: it replaces entries in sys.modules at import
time (see the stubs below), which would leak into any other test sharing the
same pytest session. Kept in the repo anyway, because deletion is destructive
and irreversible and deserves a regression guard.


The point of this test is the CROSS-ACCOUNT assertion: deleting Alice must
leave Bob completely intact. A purge that over-deletes is far worse than one
that under-deletes, and it is the failure you would never notice in manual
testing with a single account.

chromadb / sentence-transformers / cryptography are not installed on this
laptop (they live in the container), so the vector-store and memory-crypto
layers are stubbed. Everything under test -- the SQL, the ordering, the
scoping -- is the real code.
"""
import asyncio, sys, tempfile, types
from pathlib import Path

tmp = Path(tempfile.mkdtemp())
sys.path.insert(0, ".")
# Use the REAL config (it is a pure-stdlib leaf) and only repoint the paths, so
# the code under test sees genuine settings rather than a hand-rolled stub.
import config as cfg                                                  # noqa: E402
cfg.MEMORY_DB = tmp / "memory.db"
cfg.ARTIFACTS_DIR = tmp / "artifacts"
cfg.DATA_DIR = tmp
cfg.LOGS_DIR = tmp / "logs"
cfg.LOGS_DIR.mkdir(parents=True, exist_ok=True)
cfg.ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

# --- stubs for what isn't installed locally ------------------------------
auth = types.ModuleType("services.auth_service")
auth.require_chat_access = lambda: None
sys.modules["services.auth_service"] = auth

deleted_vectors = {"artifacts": [], "project_memories": []}

rag = types.ModuleType("services.rag_service")
async def _del_art(aid): deleted_vectors["artifacts"].append(aid)
async def _del_projmem(pid): deleted_vectors["project_memories"].append(pid)
rag.delete_artifact_async = _del_art
rag.delete_project_memory_vectors_async = _del_projmem
sys.modules["services.rag_service"] = rag

sys.path.insert(0, ".")

from services import project_service, conversation_service            # noqa: E402
from services.artifacts import store as artifact_store                # noqa: E402
from services.training import user_consent                            # noqa: E402

project_service.init_db(); conversation_service.init_db()
artifact_store.init_db(); user_consent.init_db()

# user_memory store needs the crypto module; stub encrypt/decrypt.
crypto = types.ModuleType("services.user_memory.crypto")
crypto.encrypt = lambda s: "enc:" + s
crypto.decrypt = lambda s: s[4:]
sys.modules["services.user_memory.crypto"] = crypto
from services.user_memory import store as mem_store                   # noqa: E402
mem_store.init_db()

import services.account_deletion as ad                                # noqa: E402

ALICE, BOB = "alice-sub-111", "bob-sub-222"

def seed(sub, email, n_conv=2, n_art=2, n_mem=1):
    pid = ad.sandbox_project_id(sub)
    project_service.ensure_project(pid, f"Attachments — {email}")
    for i in range(n_conv):
        c = conversation_service.create("default", "basic", f"{email} chat {i}",
                                        user_id=sub, owner_tier="user")
        conversation_service.add_message(c["id"], "user", "hello")
        conversation_service.add_message(c["id"], "assistant", "hi there")
    for i in range(n_art):
        rec = artifact_store.create(pid, f"n{i}.md", kind="note", mime="text/markdown",
                                    sha256=f"{sub}-h{i}", size=10, status="ready")
        # a real file on disk, so we can prove the purge removes it too
        (cfg.ARTIFACTS_DIR / pid).mkdir(parents=True, exist_ok=True)
        (cfg.ARTIFACTS_DIR / pid / f"{rec['id']}_n{i}.md").write_text("data")
    for i in range(n_mem):
        mem_store.insert_memory(pid, "fact", "s", f"secret {i}", source="test")
    user_consent.set_allowed(sub, True, email)
    return pid

def snapshot(sub):
    pid = ad.sandbox_project_id(sub)
    return {
        "conversations": len(conversation_service.list_by("default", user_id=sub)),
        "messages": sum(len(conversation_service.get(c["id"])["messages"])
                        for c in conversation_service.list_by("default", user_id=sub)),
        "artifacts": len(artifact_store.list_for_project(pid)),
        "memories": len(mem_store.list_memories(pid)),
        "project": project_service.get_project(pid) is not None,
        "consent": user_consent.get(sub)["allowed"],
        "files": len(list((cfg.ARTIFACTS_DIR / pid).glob("*"))) if (cfg.ARTIFACTS_DIR / pid).exists() else 0,
    }

seed(ALICE, "alice@example.com")
seed(BOB, "bob@example.com")

before_a, before_b = snapshot(ALICE), snapshot(BOB)
print("BEFORE alice:", before_a)
print("BEFORE bob  :", before_b)
assert all(before_a[k] for k in ("conversations", "artifacts", "memories", "project", "consent"))

result = asyncio.run(ad.purge_account(ALICE, "alice@example.com"))
print("\npurge result:", result)

after_a, after_b = snapshot(ALICE), snapshot(BOB)
print("\nAFTER  alice:", after_a)
print("AFTER  bob  :", after_b)

checks = []
def ck(name, ok): checks.append((name, ok)); print(("PASS" if ok else "FAIL"), "|", name)

print()
ck("alice conversations gone",   after_a["conversations"] == 0)
ck("alice messages gone",        after_a["messages"] == 0)
ck("alice artifacts gone",       after_a["artifacts"] == 0)
ck("alice memories gone",        after_a["memories"] == 0)
ck("alice sandbox project gone", after_a["project"] is False)
ck("alice agreement gone",       after_a["consent"] is False)
ck("alice FILES on disk gone",   after_a["files"] == 0)
ck("artifact VECTORS deleted",   len(deleted_vectors["artifacts"]) == 2)
ck("memory VECTORS deleted",     ad.sandbox_project_id(ALICE) in deleted_vectors["project_memories"])
ck("no failures reported",       result["failures"] == [])
ck("status is 'deleted'",        result["status"] == "deleted")
print()
ck("BOB conversations intact",   after_b["conversations"] == before_b["conversations"])
ck("BOB messages intact",        after_b["messages"] == before_b["messages"])
ck("BOB artifacts intact",       after_b["artifacts"] == before_b["artifacts"])
ck("BOB memories intact",        after_b["memories"] == before_b["memories"])
ck("BOB project intact",         after_b["project"] is True)
ck("BOB agreement intact",       after_b["consent"] is True)
ck("BOB files on disk intact",   after_b["files"] == before_b["files"] > 0)
print()
# The falsy-subject guard: an empty user_id must never match legacy NULL rows.
legacy = conversation_service.create("default", "basic", "operator legacy", user_id=None)
n = conversation_service.delete_all_for_user("")
ck("empty sub deletes nothing",  n == 0 and conversation_service.get(legacy["id"]) is not None)

failed = [n for n, ok in checks if not ok]
print(f"\n{len(checks)-len(failed)}/{len(checks)} passed")
sys.exit(1 if failed else 0)
