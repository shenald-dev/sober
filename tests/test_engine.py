from pathlib import Path

from sober.core.config import SoberConfig
from sober.core.engine import AuditEngine
from sober.core.scanner import FileToAudit


def _project(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "import requests\n"
        "def load(url):\n"
        "    return requests.get(url)\n"
    )
    (tmp_path / "secrets.py").write_text('KEY = "sk-' + "e" * 40 + '"\n')
    (tmp_path / "debug.py").write_text('print(f"DEBUG: x")\n')
    return [FileToAudit(tmp_path / n) for n in ("app.py", "secrets.py", "debug.py")]


def test_engine_finds_expected_rules(tmp_path):
    files = _project(tmp_path)
    engine = AuditEngine(tmp_path, config=SoberConfig(offline_mode=True), use_cache=False)
    report = engine.audit(files)
    ids = {i.rule_id for i in report.issues}
    assert "SOBER-REL001" in ids
    assert "SOBER-SEC001" in ids
    assert "SOBER-GHO005" in ids
    assert report.files_scanned == 3


def test_engine_cache_hit_second_run(tmp_path):
    files = _project(tmp_path)
    cfg = SoberConfig(offline_mode=True)
    first = AuditEngine(tmp_path, config=cfg, use_cache=True).audit(files)
    second = AuditEngine(tmp_path, config=cfg, use_cache=True).audit(files)
    assert second.cache_hits >= 3
    assert {i.rule_id for i in first.issues} == {i.rule_id for i in second.issues}


def test_engine_suppression(tmp_path):
    f = tmp_path / "s.py"
    f.write_text('KEY = "sk-' + "f" * 40 + '"  # sober: ignore[SOBER-SEC001]\n')
    engine = AuditEngine(tmp_path, config=SoberConfig(offline_mode=True), use_cache=False)
    report = engine.audit([FileToAudit(f)])
    assert report.suppressed_count == 1
    assert not any(i.rule_id == "SOBER-SEC001" for i in report.issues)


def test_engine_ignore_paths(tmp_path):
    (tmp_path / "keep.py").write_text('print(f"DEBUG: a")\n')
    sub = tmp_path / "vendor"; sub.mkdir()
    (sub / "skip.py").write_text('print(f"DEBUG: b")\n')
    cfg = SoberConfig(offline_mode=True, ignore_paths=["vendor/*"])
    files = [FileToAudit(tmp_path / "keep.py"), FileToAudit(sub / "skip.py")]
    report = AuditEngine(tmp_path, config=cfg, use_cache=False).audit(files)
    assert report.files_scanned == 1


def test_engine_disabled_detector(tmp_path):
    f = tmp_path / "d.py"
    f.write_text('print(f"DEBUG: a")\n')
    cfg = SoberConfig(offline_mode=True, disabled_detectors=["ghost_code"])
    report = AuditEngine(tmp_path, config=cfg, use_cache=False).audit([FileToAudit(f)])
    assert not any(i.rule_id == "SOBER-GHO005" for i in report.issues)


def test_engine_deterministic_order(tmp_path):
    files = _project(tmp_path)
    cfg = SoberConfig(offline_mode=True)
    a = AuditEngine(tmp_path, config=cfg, use_cache=False).audit(files)
    b = AuditEngine(tmp_path, config=cfg, use_cache=False).audit(files)
    assert [(i.file_path, i.line_number, i.rule_id) for i in a.issues] ==            [(i.file_path, i.line_number, i.rule_id) for i in b.issues]
