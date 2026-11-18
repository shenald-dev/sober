from sober.core.rules import CATALOG, SECURITY_SEVERITY, all_rules, finding_fingerprint, get_rule
from sober.detectors import Severity


def test_catalog_ids_unique_and_prefixed():
    rules = all_rules()
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids))
    assert all(i.startswith("SOBER-") for i in ids)
    assert len(rules) >= 40


def test_every_severity_has_security_score():
    for sev in Severity:
        assert sev in SECURITY_SEVERITY
    for rule in all_rules():
        assert rule.security_severity == SECURITY_SEVERITY[rule.severity]


def test_get_rule_roundtrip():
    assert get_rule("SOBER-SEC007").severity == Severity.CRITICAL
    assert get_rule("SOBER-NOPE") is None
    assert CATALOG["SOBER-HAL001"].category == "Hallucinated Dependency"


def test_fingerprint_stable_and_line_independent():
    a = finding_fingerprint("SOBER-SEC001", "src/app.py", "key = 'sk-abc'")
    b = finding_fingerprint("SOBER-SEC001", "src/app.py", "key   =   'sk-abc'")
    c = finding_fingerprint("SOBER-SEC001", "src/other.py", "key = 'sk-abc'")
    assert a == b
    assert a != c
    assert len(a) == 32


def test_rule_to_dict_shape():
    d = get_rule("SOBER-VUL001").to_dict()
    assert d["id"] == "SOBER-VUL001"
    assert d["severity"] == "HIGH"
    assert "injection" in d["tags"]
