"""Git-repository source connector.

Acquires an approved upstream repo with a **shallow, pinned** clone (arg array,
``shell=False``, timeouts), resolves the exact commit SHA for provenance, then
walks the profile's include/exclude globs, normalizing each matched text file
into a :class:`NormalizedDoc` with a canonical ``blob`` source URL.

Nothing from the repo is executed. Only text files under the declared file types
are read, each capped to a byte limit, with an overall file-count cap.
"""

from __future__ import annotations

import fnmatch
import subprocess
from pathlib import Path
from urllib.parse import urlparse

import config

from . import injection_scan, markdown
from .base import ConnectorProfile, NormalizedDoc, SourceConnector


def _git(*args: str, cwd: str | None = None, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        shell=False,
    )


class GitConnector(SourceConnector):
    def health(self) -> dict:
        try:
            r = _git("--version", timeout=10)
            if r.returncode == 0:
                return {"available": True, "reason": None, "git": r.stdout.strip()}
            return {"available": False, "reason": "git not runnable"}
        except (OSError, subprocess.SubprocessError) as e:
            return {"available": False, "reason": f"git unavailable: {e}"}

    # --- version discovery (network-only, no clone) --------------------------
    def discover_version(self) -> str | None:
        repo = self.profile.repo_url
        if not repo:
            return None
        try:
            r = _git("ls-remote", repo, self.profile.default_ref,
                     timeout=config.KNOWLEDGE_CONNECTOR_NET_TIMEOUT)
            if r.returncode != 0 or not r.stdout.strip():
                # ref may be a tag or the default HEAD
                r = _git("ls-remote", repo, "HEAD",
                         timeout=config.KNOWLEDGE_CONNECTOR_NET_TIMEOUT)
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout.split()[0]
        except (OSError, subprocess.SubprocessError):
            return None
        return None

    def _host_allowed(self) -> bool:
        if not self.profile.allowed_hosts:
            return True
        host = (urlparse(self.profile.repo_url or "").hostname or "").lower()
        return host in {h.lower() for h in self.profile.allowed_hosts}

    # --- acquisition ---------------------------------------------------------
    def _sparse_dirs(self) -> list[str] | None:
        """Top-level directory anchors derivable from every declared
        include_glob (e.g. ``"Detections/**/*.yaml"`` -> ``"/Detections"``).
        Returns ``None`` when any glob has no clear leading directory (e.g.
        ``"**/*.md"``) — sparse selection is only attempted when it can
        losslessly narrow the checkout, never when it might drop a file a
        full clone would have matched."""
        globs = self.profile.include_globs or ()
        if not globs:
            return None
        dirs: set[str] = set()
        for g in globs:
            prefix = g.split("*", 1)[0].rstrip("/")
            if not prefix or prefix == g:
                return None
            dirs.add("/" + prefix)
        return sorted(dirs)

    def acquire(self, workdir) -> str:
        if not self._host_allowed():
            raise PermissionError(
                f"repo host not in connector allow-list: {self.profile.repo_url}")
        repo = self.profile.repo_url
        if not repo:
            raise ValueError("connector has no repo_url")
        dest = str(Path(workdir) / "repo")
        ct = config.KNOWLEDGE_CONNECTOR_CLONE_TIMEOUT

        # Fast path: a partial + sparse clone fetches only the directories the
        # include_globs actually need — large monorepos (e.g. Azure-Sentinel,
        # gigabytes of workbooks/notebooks outside the ~500 detection YAMLs we
        # want) clone in seconds instead of timing out. Only attempted when
        # every include_glob has an unambiguous directory prefix; any failure
        # falls through to the exact full-clone path below, unchanged.
        sparse_dirs = self._sparse_dirs()
        if sparse_dirs:
            r = _git("clone", "--depth", "1", "--filter=blob:none", "--sparse",
                     "--branch", self.profile.default_ref, "--single-branch",
                     repo, dest, timeout=ct)
            if r.returncode == 0:
                # `sparse-checkout set` (without --skip-checkout) also updates
                # the working tree to match the new patterns — for a large
                # monorepo with several sparse directories that's real blob-
                # fetching work, not just a config write, so it shares the
                # same configurable budget as the clone step rather than a
                # fixed 60s (a fixed cap here reintroduced exactly the kind of
                # large-repo timeout this sparse-clone path exists to avoid).
                sp = _git("sparse-checkout", "set", "--no-cone", *sparse_dirs,
                         cwd=dest, timeout=ct)
                _git("checkout", cwd=dest, timeout=ct)
                if sp.returncode == 0 and any(Path(dest, d.lstrip("/")).exists() for d in sparse_dirs):
                    sha = _git("rev-parse", "HEAD", cwd=dest, timeout=30)
                    return sha.stdout.strip() if sha.returncode == 0 else self.profile.default_ref
            # Sparse attempt didn't pan out — remove any partial dest and fall
            # through to the full clone below.
            import shutil as _shutil
            _shutil.rmtree(dest, ignore_errors=True)

        r = _git("clone", "--depth", "1", "--branch", self.profile.default_ref,
                 "--single-branch", repo, dest, timeout=ct)
        if r.returncode != 0:
            # retry without --branch (default branch) in case the ref is HEAD
            r = _git("clone", "--depth", "1", "--single-branch", repo, dest, timeout=ct)
            if r.returncode != 0:
                raise RuntimeError(f"git clone failed: {r.stderr.strip()[:300]}")
        sha = _git("rev-parse", "HEAD", cwd=dest, timeout=30)
        return sha.stdout.strip() if sha.returncode == 0 else self.profile.default_ref

    # --- normalization -------------------------------------------------------
    def _matches(self, rel: str) -> bool:
        globs = self.profile.include_globs or ()
        inc = any(fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(rel, g.replace("**/", ""))
                  for g in globs)
        # Suffix fallback only when NO include_globs are declared. When a profile
        # DOES declare globs they are the authoritative allow-list — otherwise a
        # generic file_type (e.g. ".yml") would silently pull in every such file
        # in the repo (workflows, tests, regression data), defeating the globs.
        if not inc and not globs and self.profile.file_types:
            inc = rel.lower().endswith(tuple(t.lower() for t in self.profile.file_types))
        if not inc:
            return False
        for g in self.profile.exclude_globs:
            if fnmatch.fnmatch(rel, g):
                return False
        return True

    def _blob_url(self, ref: str, rel: str) -> str | None:
        tpl = self.profile.blob_url_template
        if not tpl:
            return self.profile.upstream_url
        repo = self.profile.repo_url or ""
        if repo.endswith(".git"):
            repo = repo[:-4]
        repo = repo.rstrip("/")
        return tpl.format(repo=repo, ref=ref, path=rel)

    def normalize(self, acquired, workdir) -> list[NormalizedDoc]:
        ref = acquired
        root = Path(workdir) / "repo"
        max_files = self.profile.max_files or config.KNOWLEDGE_CONNECTOR_MAX_FILES
        max_bytes = self.profile.max_file_bytes or config.KNOWLEDGE_CONNECTOR_MAX_FILE_BYTES
        total_budget = config.KNOWLEDGE_CONNECTOR_MAX_TOTAL_BYTES

        docs: list[NormalizedDoc] = []
        total = 0
        # deterministic ordering
        candidates = sorted(
            p for p in root.rglob("*") if p.is_file())
        for p in candidates:
            if len(docs) >= max_files or total >= total_budget:
                break
            rel = p.relative_to(root).as_posix()
            if rel.startswith(".git/") or not self._matches(rel):
                continue
            try:
                if p.stat().st_size > max_bytes:
                    continue
                raw = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if not raw.strip():
                continue
            clean, findings = injection_scan.neutralize(raw)
            title = markdown.document_title(clean, rel.rsplit("/", 1)[-1])
            docs.append(NormalizedDoc(
                rel_path=rel,
                title=title,
                section=title,
                heading_path=(title,),
                content=clean,
                source_url=self._blob_url(ref, rel),
                source_path=rel,
                injection=findings,
            ))
            total += len(clean)
        return docs
