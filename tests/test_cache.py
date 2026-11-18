from sober.core.cache import AuditCache
from sober.detectors import Issue, Severity


def _issue():
    return Issue("Security & Secrets", "Key", "desc", Severity.CRITICAL, "a.py", 3,
                 rule_id="SOBER-SEC001")


def test_cache_roundtrip(tmp_path):
    cache = AuditCache(tmp_path, enabled=True)
    assert cache.get("hash1", "cfg1") is None
    cache.put("hash1", "cfg1", [_issue()])
    cache.flush()
    reopened = AuditCache(tmp_path, enabled=True)
    got = reopened.get("hash1", "cfg1")
    assert got is not None
    assert got[0].rule_id == "SOBER-SEC001"
    assert got[0].severity == Severity.CRITICAL
    assert reopened.hits == 1


def test_cache_config_invalidation(tmp_path):
    cache = AuditCache(tmp_path, enabled=True)
    cache.put("hash1", "cfg1", [_issue()])
    assert cache.get("hash1", "cfg2") is None
    assert cache.misses == 1


def test_cache_disabled(tmp_path):
    cache = AuditCache(tmp_path, enabled=False)
    cache.put("hash1", "cfg1", [_issue()])
    assert cache.get("hash1", "cfg1") is None


def test_cache_corruption_safe(tmp_path):
    cache = AuditCache(tmp_path, enabled=True)
    cache.path.write_text("{ not json")
    reopened = AuditCache(tmp_path, enabled=True)
    assert reopened.get("x", "y") is None
