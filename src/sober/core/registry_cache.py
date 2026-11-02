"""
Persistent disk and memory cache for package registry verification.
Prevents redundant network calls to PyPI and npm registries across runs.
"""

import json
import os
import sys
import threading
import time
from pathlib import Path

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
        self._load()

    def _load(self):
        with self._lock:
            if self.cache_file.is_file():
                try:
                    data = json.loads(self.cache_file.read_text(encoding="utf-8"))
                    now = time.time()
                    # Filter out expired entries
                    self._cache = {
                        k: v for k, v in data.items()
                        if isinstance(v, dict) and v.get("expires_at", 0) > now
                    }
                except Exception:
                    self._cache = {}

    def save(self):
        with self._lock:
            try:
                self.cache_file.write_text(json.dumps(self._cache, indent=2), encoding="utf-8")
            except OSError:
                return

    def get(self, key: str) -> bool | None:
        """Get cached validity status for a package (True, False, or None if not cached)."""
        with self._lock:
            entry = self._cache.get(key)
            if not entry:
                return None
            if entry.get("expires_at", 0) <= time.time():
                del self._cache[key]
                return None
            return entry.get("is_valid")

    def set(self, key: str, is_valid: bool):
        """Set validity status with appropriate TTL."""
        with self._lock:
            ttl = CONFIRMED_TTL_SECONDS if is_valid else NOT_FOUND_TTL_SECONDS
            self._cache[key] = {
                "is_valid": is_valid,
                "expires_at": time.time() + ttl,
            }
        self.save()


# Singleton global registry cache
global_registry_cache = RegistryCache()
