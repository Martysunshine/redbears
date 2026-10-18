"""Offline checks for the upload/storage limits. RUN DIRECTLY, not via pytest:

    cd oyster/backend && python tests/standalone_upload_limits_check.py

The scenario that motivated these limits: attachments became public, and a
signed-in account could upload 100 files a day at 500 MB each — 50 GB against
~27 GB of free disk. Counting uploads does not bound bytes, so the byte cap is
the check that actually matters, and the free-disk floor is the backstop that
holds even if the per-caller maths is wrong.
"""
import sys, types
from pathlib import Path
import tempfile

sys.path.insert(0, ".")
import config as cfg
tmp = Path(tempfile.mkdtemp())
cfg.MEMORY_DB = tmp / "memory.db"
cfg.ARTIFACTS_DIR = tmp / "artifacts"
cfg.DATA_DIR = tmp
cfg.ANON_MAX_STORAGE_MB = 10
cfg.USER_MAX_STORAGE_MB = 50
cfg.MIN_FREE_DISK_GB = 5.0

# auth_service pulls in jose, which isn't installed on this laptop.
auth = types.ModuleType("services.auth_service")
auth.require_chat_access = lambda: None
sys.modules["services.auth_service"] = auth

# chromadb/sentence-transformers live in the container, not on this laptop.
# Only the artifact STORE is under test here, not the vector pipeline.
rag = types.ModuleType("services.rag_service")
async def _noop(*a, **k): return None
for fn in ("delete_artifact_async", "delete_project_memory_vectors_async",
           "ingest_segments_async", "ingest_artifact_async"):
    setattr(rag, fn, _noop)
sys.modules["services.rag_service"] = rag

from fastapi import HTTPException                                     # noqa: E402
from services import artifact_scope as A, project_service            # noqa: E402
from services.artifacts import store as astore                       # noqa: E402

project_service.init_db(); A.init_db(); astore.init_db()

checks = []
def ck(name, ok, detail=""):
    checks.append((name, ok))
    print(f"{'PASS' if ok else 'FAIL'} | {name}{('  ' + detail) if detail else ''}")

MB = 1 << 20
alice = {"tier": "user", "sub": "alice", "email": "a@x.com", "ip": "1.1.1.1"}
guest = {"tier": "anon", "ip": "2.2.2.2"}
op    = {"tier": "admin", "sub": "op", "email": "op@x.com", "ip": "3.3.3.3"}

pa = A.scope_for(alice, "default")
pg = A.scope_for(guest, "default")
sa = A.ArtifactScope(pa, alice)
sg = A.ArtifactScope(pg, guest)
so = A.ArtifactScope("default", op)

# ---- caps are per tier -------------------------------------------------
ck("user cap = 50 MB",  A.storage_cap_bytes("user") == 50 * MB)
ck("anon cap = 10 MB",  A.storage_cap_bytes("anon") == 10 * MB)
ck("admin effectively uncapped", A.storage_cap_bytes("admin") > 1_000_000 * MB)

# ---- an empty account can store; a full one cannot ---------------------
try:
    sa.assert_can_store(5 * MB); ok = True
except HTTPException:
    ok = False
ck("fresh account may upload", ok)

def add(project_id, size, tag):
    astore.create(project_id, f"{tag}.bin", kind="file", mime="application/octet-stream",
                  sha256=f"{project_id}-{tag}", size=size, status="ready")

add(pa, 45 * MB, "big")                       # alice now at 45/50 MB
ck("usage summed from the artifacts table", A.storage_used_bytes(pa) == 45 * MB,
   f"{A.storage_used_bytes(pa)/MB:.0f} MB")
try:
    sa.assert_can_store(4 * MB); under = True
except HTTPException:
    under = False
ck("upload that FITS is allowed", under)

try:
    sa.assert_can_store(10 * MB); over_allowed = True
    detail = ""
except HTTPException as e:
    over_allowed = False; detail = str(e.detail)[:60]
ck("upload that EXCEEDS the cap is refused", not over_allowed, detail)

# ---- deleting frees allowance (why we sum instead of counting) ---------
astore.delete([r["id"] for r in astore.list_for_project(pa)][0])
try:
    sa.assert_can_store(10 * MB); freed = True
except HTTPException:
    freed = False
ck("deleting an attachment frees allowance", freed,
   f"now {A.storage_used_bytes(pa)/MB:.0f} MB used")

# ---- tenants are independent -------------------------------------------
add(pa, 49 * MB, "fill")
try:
    sg.assert_can_store(5 * MB); guest_ok = True
except HTTPException:
    guest_ok = False
ck("one account filling up does NOT block another", guest_ok)

# ---- anon has the tighter cap ------------------------------------------
add(pg, 9 * MB, "guestfile")
try:
    sg.assert_can_store(5 * MB); anon_over = True
except HTTPException:
    anon_over = False
ck("anon cap enforced at 10 MB", not anon_over,
   f"used {A.storage_used_bytes(pg)/MB:.0f} MB")

# ---- the disk floor overrides everything, operators included -----------
real_free = A.free_disk_bytes
A.free_disk_bytes = lambda: 1 * (1 << 30)     # pretend only 1 GB left
try:
    sa.assert_can_store(1); user_blocked = False
except HTTPException as e:
    user_blocked = (e.status_code == 507)
ck("disk floor blocks a normal account", user_blocked)
try:
    so.assert_can_store(1); op_blocked = False
except HTTPException as e:
    op_blocked = (e.status_code == 507)
ck("disk floor blocks OPERATORS too", op_blocked)
A.free_disk_bytes = real_free

try:
    so.assert_can_store(900 * MB); op_free = True
except HTTPException:
    op_free = False
ck("operators otherwise uncapped", op_free)

# ---- daily counts still apply ------------------------------------------
hit = None
for i in range(1, 40):
    try:
        A.consume_upload(guest)
    except HTTPException:
        hit = i; break
ck("anon daily upload count still enforced", hit == A.ANON_DAILY_UPLOADS + 1,
   f"tripped at attempt {hit}, limit {A.ANON_DAILY_UPLOADS}")

failed = [n for n, ok in checks if not ok]
print(f"\n{len(checks)-len(failed)}/{len(checks)} passed")
sys.exit(1 if failed else 0)
