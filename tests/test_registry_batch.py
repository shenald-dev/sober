from sober.core.registry_cache import RegistryCache


def test_set_many_single_write(tmp_path, monkeypatch):
    cache = RegistryCache(tmp_path / "c.json")
    writes = {"n": 0}
    orig = cache.save

    def counting():
        writes["n"] += 1
        orig()

    monkeypatch.setattr(cache, "save", counting)
    cache.set_many({f"pypi:p{i}": True for i in range(20)})
    assert writes["n"] == 1
    reopened = RegistryCache(tmp_path / "c.json")
    assert reopened.get("pypi:p19") is True


def test_save_skips_when_clean(tmp_path, monkeypatch):
    cache = RegistryCache(tmp_path / "c.json")
    cache.set("pypi:x", True)
    writes = {"n": 0}
    orig_replace = __import__("os").replace

    def counting(*a, **k):
        writes["n"] += 1
        return orig_replace(*a, **k)

    monkeypatch.setattr("os.replace", counting)
    cache.save()
    cache.save()
    assert writes["n"] == 0
