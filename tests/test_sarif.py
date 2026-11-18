from sober import __version__
from sober.core.scorer import SoberAuditReport
from sober.detectors import Issue, Severity


def _report():
    issues = [
        Issue("Security & Secrets", "OpenAI key", "desc", Severity.CRITICAL, "a.py", 5,
              code_snippet="sk-xxxx", rule_id="SOBER-SEC001"),
        Issue("Debug Debris", "print", "desc", Severity.LOW, "b.py", 2,
              code_snippet="print('DEBUG')", rule_id="SOBER-GHO005"),
    ]
    return SoberAuditReport(issues, files_scanned=2, duration_seconds=0.1)


def test_sarif_version_and_rules():
    sarif = _report().to_sarif()
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["version"] == __version__
    rule_ids = {r["id"] for r in driver["rules"]}
    assert rule_ids == {"SOBER-SEC001", "SOBER-GHO005"}
    sec = next(r for r in driver["rules"] if r["id"] == "SOBER-SEC001")
    assert sec["properties"]["security-severity"] == "9.5"


def test_sarif_fingerprints_and_uribase():
    sarif = _report().to_sarif()
    for result in sarif["runs"][0]["results"]:
        assert "soberFindingHash/v1" in result["partialFingerprints"]
        loc = result["locations"][0]["physicalLocation"]["artifactLocation"]
        assert loc["uriBaseId"] == "%SRCROOT%"


def test_to_dict_schema_and_extras():
    d = _report().to_dict()
    assert d["schema_version"] == "3.0"
    assert "suppressed" in d
    assert "cache" in d
    assert d["issues"][0]["rule_id"] == "SOBER-SEC001"
