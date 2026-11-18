"""
Incremental audit-result cache.

Caches per-file findings keyed by content hash plus a configuration fingerprint, so
unchanged files are not re-scanned on repeated runs (watch mode, pre-commit, CI).
The cache is advisory: any miss, corruption or version change simply falls back to a
full scan. Entries are bounded and persisted with a single atomic write per run.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path

from sober.core.registry_cache import get_cache_file_path
from sober.detectors import Issue

logger = logging.getLogger(__name__)

MAX_ENTRIES = 5000


def _audit_cache_path(root: Path) -> Path:
    import hashlib

    digest = hashlib.sha256(str(root.resolve()).encode("utf-8")).hexdigest()[:16]
    base = get_cache_file_path().parent / "audit"
    base.mkdir(parents=True, exist_ok=True)
    return base / f"{digest}.json"


class AuditCache:
    def __init__(self, root: Path, enabled: bool = True):
        self.enabled = enabled
        self.path = _audit_cache_path(root)
        self._entries: dict[str, dict] = {}
        self._dirty = False
        self.hits = 0
        self.misses = 0
        if enabled:
            self._load()

    def _load(self):
        try:
            if self.path.is_file():
                data = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    self._entries = data.get("entries", {})
        except (OSError, ValueError):
            logger.debug("Failed to load audit cache %s", self.path, exc_info=True)
            self._entries = {}

    def get(self, content_hash: str, config_key: str) -> list[Issue] | None:
        if not self.enabled:
            return None
        entry = self._entries.get(content_hash)
        if not entry or entry.get("config_key") != config_key:
            self.misses += 1
            return None
        try:
            issues = [Issue.from_dict(d) for d in entry["issues"]]
        except (KeyError, ValueError, TypeError):
            self.misses += 1
            return None
        entry["ts"] = time.time()
        self.hits += 1
        return issues

    def put(self, content_hash: str, config_key: str, issues: list[Issue]):
        if not self.enabled:
            return
        self._entries[content_hash] = {
            "config_key": config_key,
            "issues": [i.to_dict() for i in issues],
            "ts": time.time(),
        }
        self._dirty = True
        if len(self._entries) > MAX_ENTRIES:
            ordered = sorted(self._entries.items(), key=lambda kv: kv[1].get("ts", 0))
            for key, _ in ordered[: len(self._entries) - MAX_ENTRIES]:
                del self._entries[key]

    def flush(self):
        if not self.enabled or not self._dirty:
            return
        try:
            tmp = self.path.with_suffix(".json.tmp")
            tmp.write_text(
                json.dumps({"entries": self._entries}, separators=(",", ":")),
                encoding="utf-8",
            )
            os.replace(tmp, self.path)
            self._dirty = False
        except OSError:
            logger.debug("Failed to persist audit cache", exc_info=True)
