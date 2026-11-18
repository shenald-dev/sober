"""
Persistent disk and memory cache for package registry verification.

Prevents redundant network calls to PyPI and npm across runs. Writes are batched:
``set_many`` records many verdicts and persists them with a single atomic write,
which removes the per-package full-file rewrite of the legacy hot path.
"""

import json
import logging
import os
import sys
import threading
import time
from pathlib import Path

logger = logging.getLogger(__name__)

# TTL settings: 24 hours for confirmed packages, 1 hour for confirmed 404s
CONFIRMED_TTL_SECONDS = 86400
NOT_FOUND_TTL_SECONDS = 3600


def get_cache_file_path() -> Path:
    """Resolve OS-appropriate cache directory for SOBER."""
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    cache_dir = base / "sober"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir / "registry_cache.json"


class RegistryCache:
    def __init__(self, cache_file: Path | None = None):
        self.cache_file = cache_file or get_cache_file_path()
        self._lock = threading.Lock()
        self._cache: dict[str, dict] = {}
        self._dirty = False
        self._load()

    def _load(self):
        with self._lock:
            if self.cache_file.is_file():
                try:
                    data = json.loads(self.cache_file.read_text(encoding="utf-8"))
                    now = time.time()
                    self._cache = {
                        k: v
                        for k, v in data.items()
                        if isinstance(v, dict) and v.get("expires_at", 0) > now
                    }
                except (OSError, ValueError):
                    logger.debug("Failed to load cache from %s", self.cache_file, exc_info=True)
                    self._cache = {}

    def save(self):
        """Atomically persist the cache if it changed since the last write."""
        with self._lock:
            if not self._dirty:
                return
            snapshot = dict(self._cache)
            self._dirty = False
        try:
            tmp = self.cache_file.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(snapshot, separators=(",", ":")), encoding="utf-8")
            os.replace(tmp, self.cache_file)
        except OSError:
            logger.debug("Failed to persist registry cache", exc_info=True)

    def get(self, key: str) -> bool | None:
        """Get cached validity status for a package (True, False, or None if not cached)."""
        with self._lock:
            entry = self._cache.get(key)
            if not entry:
                return None
            if entry.get("expires_at", 0) <= time.time():
                del self._cache[key]
                self._dirty = True
                return None
            return entry.get("is_valid")

    def _record(self, key: str, is_valid: bool):
        ttl = CONFIRMED_TTL_SECONDS if is_valid else NOT_FOUND_TTL_SECONDS
        self._cache[key] = {"is_valid": is_valid, "expires_at": time.time() + ttl}
        self._dirty = True

    def set(self, key: str, is_valid: bool):
        """Set validity status with appropriate TTL and persist immediately."""
        with self._lock:
            self._record(key, is_valid)
        self.save()

    def set_many(self, items: dict[str, bool]):
        """Record many verdicts under one lock and persist with a single write."""
        if not items:
            return
        with self._lock:
            for key, is_valid in items.items():
                self._record(key, is_valid)
        self.save()


# Singleton global registry cache
global_registry_cache = RegistryCache()
