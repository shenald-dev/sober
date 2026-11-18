from sober.core.context import FileContext
from sober.core.scanner import FileToAudit


def test_context_reads_once(tmp_path, monkeypatch):
    f = tmp_path / "a.py"
    f.write_text("import os\nvalue = 1\n")
    fa = FileToAudit(f)
    calls = {"n": 0}
    orig = fa.read_text

    def counting():
        calls["n"] += 1
        return orig()

    monkeypatch.setattr(fa, "read_text", counting)
    ctx = FileContext(fa)
    _ = ctx.content
    _ = ctx.lines
    _ = ctx.tree
    _ = ctx.tree
    _ = ctx.content_hash
    assert calls["n"] == 1
    assert ctx.tree is not None
    assert len(ctx.content_hash) == 64


def test_context_syntax_error_tree_none(tmp_path):
    f = tmp_path / "bad.py"
    f.write_text("def broken(:\n")
    ctx = FileContext(FileToAudit(f))
    assert ctx.tree is None


def test_context_content_override(tmp_path):
    f = tmp_path / "a.py"
    f.write_text("working = 1\n")
    ctx = FileContext(FileToAudit(f), content="staged = 2\n")
    assert ctx.content == "staged = 2\n"
    assert "staged" in ctx.lines[0]


def test_context_non_python_tree_none(tmp_path):
    f = tmp_path / "a.js"
    f.write_text("const x = 1;\n")
    ctx = FileContext(FileToAudit(f))
    assert ctx.tree is None


def test_context_in_diff(tmp_path):
    f = tmp_path / "a.py"
    f.write_text("a\nb\nc\n")
    ctx = FileContext(FileToAudit(f, diff_lines={2}))
    assert ctx.in_diff(2) is True
    assert ctx.in_diff(1) is False
    assert FileContext(FileToAudit(f)).in_diff(99) is True
