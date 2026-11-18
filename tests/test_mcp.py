import io
import json
import subprocess
import sys
from pathlib import Path

from sober.mcp.server import LATEST_VERSION, MCPServer


def _run(root: Path, messages: list[str]) -> list[dict]:
    stdin = io.StringIO("\n".join(messages) + "\n")
    stdout = io.StringIO()
    MCPServer(root, stdin=stdin, stdout=stdout).serve()
    return [json.loads(line) for line in stdout.getvalue().splitlines() if line.strip()]


def _init(req_id=1, version="2025-06-18"):
    return json.dumps({"jsonrpc": "2.0", "id": req_id, "method": "initialize",
                       "params": {"protocolVersion": version, "capabilities": {},
                                  "clientInfo": {"name": "test", "version": "0"}}})


def _initialized():
    return json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"})


def test_initialize_handshake(tmp_path):
    out = _run(tmp_path, [_init(), _initialized()])
    assert len(out) == 1
    result = out[0]["result"]
    assert result["protocolVersion"] == "2025-06-18"
    assert result["serverInfo"]["name"] == "sober"
    assert "tools" in result["capabilities"]
    assert result["instructions"]


def test_version_negotiation_fallback(tmp_path):
    out = _run(tmp_path, [_init(version="1999-01-01")])
    assert out[0]["result"]["protocolVersion"] == LATEST_VERSION


def test_tools_list(tmp_path):
    out = _run(tmp_path, [_init(), _initialized(),
                          json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})])
    tools = out[-1]["result"]["tools"]
    names = {t["name"] for t in tools}
    assert names == {"sober_scan", "sober_explain", "sober_cure", "sober_rules"}
    scan = next(t for t in tools if t["name"] == "sober_scan")
    assert scan["annotations"]["readOnlyHint"] is True
    assert "inputSchema" in scan


def test_scan_tool_structured(tmp_path):
    (tmp_path / "bad.py").write_text('KEY = "sk-' + "z" * 40 + '"\n')
    call = json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                       "params": {"name": "sober_scan", "arguments": {"scope": "all"}}})
    out = _run(tmp_path, [_init(), _initialized(), call])
    result = out[-1]["result"]
    assert result["isError"] is False
    assert "structuredContent" in result
    assert result["structuredContent"]["sober_score"] < 100
    assert any(i["rule_id"] == "SOBER-SEC001" for i in result["structuredContent"]["issues"])


def test_rules_tool(tmp_path):
    call = json.dumps({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                       "params": {"name": "sober_rules", "arguments": {}}})
    out = _run(tmp_path, [_init(), _initialized(), call])
    assert out[-1]["result"]["structuredContent"]["count"] >= 40


def test_unknown_tool_protocol_error(tmp_path):
    call = json.dumps({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                       "params": {"name": "nope", "arguments": {}}})
    out = _run(tmp_path, [_init(), _initialized(), call])
    assert out[-1]["error"]["code"] == -32602


def test_path_traversal_rejected(tmp_path):
    call = json.dumps({"jsonrpc": "2.0", "id": 6, "method": "tools/call",
                       "params": {"name": "sober_scan", "arguments": {"path": "../../"}}})
    out = _run(tmp_path, [_init(), _initialized(), call])
    assert out[-1]["result"]["isError"] is True


def test_malformed_json_parse_error(tmp_path):
    out = _run(tmp_path, ["{ not json"])
    assert out[0]["error"]["code"] == -32700


def test_batch_rejected(tmp_path):
    out = _run(tmp_path, ["[]"])
    assert out[0]["error"]["code"] == -32600


def test_ping(tmp_path):
    out = _run(tmp_path, [_init(), _initialized(),
                          json.dumps({"jsonrpc": "2.0", "id": 9, "method": "ping"})])
    assert out[-1]["result"] == {}


def test_unknown_method(tmp_path):
    out = _run(tmp_path, [_init(), _initialized(),
                          json.dumps({"jsonrpc": "2.0", "id": 10, "method": "foo/bar"})])
    assert out[-1]["error"]["code"] == -32601


def test_cure_dry_run_then_apply(tmp_path):
    f = tmp_path / "d.py"
    f.write_text('print(f"DEBUG: x")\nvalue = 1\n')
    dry = json.dumps({"jsonrpc": "2.0", "id": 11, "method": "tools/call",
                      "params": {"name": "sober_cure", "arguments": {"scope": "all", "dry_run": True}}})
    out = _run(tmp_path, [_init(), _initialized(), dry])
    assert out[-1]["result"]["structuredContent"]["dry_run"] is True
    assert "DEBUG" in f.read_text()
    apply = json.dumps({"jsonrpc": "2.0", "id": 12, "method": "tools/call",
                        "params": {"name": "sober_cure", "arguments": {"scope": "all", "dry_run": False}}})
    out = _run(tmp_path, [_init(), _initialized(), apply])
    assert out[-1]["result"]["structuredContent"]["total"] >= 1
    assert "DEBUG" not in f.read_text()
    assert "value = 1" in f.read_text()


def test_structured_absent_on_old_protocol(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    call = json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                       "params": {"name": "sober_scan", "arguments": {"scope": "all"}}})
    out = _run(tmp_path, [_init(version="2024-11-05"), _initialized(), call])
    assert "structuredContent" not in out[-1]["result"]


def test_stdio_entrypoint_smoke(tmp_path):
    import os
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src") + os.pathsep + env.get("PYTHONPATH", "")
    payload = _init() + "\n" + _initialized() + "\n" + json.dumps(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}) + "\n"
    proc = subprocess.run([sys.executable, "-m", "sober.mcp", "--path", str(tmp_path)],
                          input=payload, capture_output=True, text=True, env=env, timeout=30)
    lines = [json.loads(x) for x in proc.stdout.splitlines() if x.strip()]
    assert lines[0]["result"]["serverInfo"]["name"] == "sober"
    assert any(t["name"] == "sober_scan" for t in lines[-1]["result"]["tools"])
