import time

from sober.core.registry_cache import RegistryCache


def test_registry_cache_get_set(tmp_path):
    cache_file = tmp_path / "test_cache.json"
    cache = RegistryCache(cache_file)

    assert cache.get("pypi:requests") is None

    cache.set("pypi:requests", True)
    assert cache.get("pypi:requests") is True

    cache.set("pypi:nonexistent", False)
    assert cache.get("pypi:nonexistent") is False

    # Verify disk persistence across instances
    cache2 = RegistryCache(cache_file)
    assert cache2.get("pypi:requests") is True
    assert cache2.get("pypi:nonexistent") is False


def test_registry_cache_expiration(tmp_path):
    cache_file = tmp_path / "test_cache.json"
    cache = RegistryCache(cache_file)

    # Force an expired entry
    cache._cache["expired-pkg"] = {
        "is_valid": True,
        "expires_at": time.time() - 100,
    }

    assert cache.get("expired-pkg") is None
