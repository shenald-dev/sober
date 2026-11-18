"""
Zero-dependency MCP stdio server (JSON-RPC 2.0).

Implements the Model Context Protocol lifecycle (initialize -> initialized ->
operation -> shutdown), version negotiation, ping, tools/list and tools/call with
structured content. Only valid MCP messages are written to stdout; diagnostics go
to stderr. Request lines are size-bounded to prevent memory exhaustion.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

from sober import __version__
from sober.mcp.tools import ToolRegistry

logger = logging.getLogger("sober.mcp")

SUPPORTED_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
LATEST_VERSION = SUPPORTED_VERSIONS[0]
MAX_MESSAGE_BYTES = 8 * 1024 * 1024

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

INSTRUCTIONS = (
    "SOBER audits AI-generated code for hallucinated dependencies, secret leaks, "
    "reliability antipatterns and ghost code. Call sober_scan before committing or "
    "after generating code; use sober_explain to get a surgical remediation directive; "
    "use sober_cure (dry_run first) to strip debug debris. Findings carry stable "
    "SOBER-* rule IDs and a 0-100 sobriety score."
)


class MCPServer:
    def __init__(self, root: Path, stdin=None, stdout=None):
        self.root = root.resolve()
        self.registry = ToolRegistry(self.root)
        self.stdin = stdin if stdin is not None else sys.stdin
        self.stdout = stdout if stdout is not None else sys.stdout
        self.protocol_version = LATEST_VERSION
        self.initialized = False

    def _send(self, message: dict):
        line = json.dumps(message, separators=(",", ":"), ensure_ascii=False)
        self.stdout.write(line + "\n")
        self.stdout.flush()

    def _result(self, msg_id, result: dict):
        self._send({"jsonrpc": "2.0", "id": msg_id, "result": result})

    def _error(self, msg_id, code: int, message: str, data=None):
        err = {"code": code, "message": message}
        if data is not None:
            err["data"] = data
        self._send({"jsonrpc": "2.0", "id": msg_id, "error": err})

    def _structured_ok(self, msg_id, structured: dict, text: str):
        result = {"content": [{"type": "text", "text": text}], "isError": False}
        if self.protocol_version >= "2025-06-18":
            result["structuredContent"] = structured
        self._result(msg_id, result)

    def _tool_error(self, msg_id, text: str):
        self._result(msg_id, {"content": [{"type": "text", "text": text}], "isError": True})

    def _handle_initialize(self, msg_id, params: dict):
        requested = params.get("protocolVersion", LATEST_VERSION)
        self.protocol_version = requested if requested in SUPPORTED_VERSIONS else LATEST_VERSION
        self._result(msg_id, {
            "protocolVersion": self.protocol_version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "sober", "title": "SOBER Code Sobriety Auditor", "version": __version__},
            "instructions": INSTRUCTIONS,
        })

    def _handle_tools_call(self, msg_id, params: dict):
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            self._error(msg_id, INVALID_PARAMS, "Tool arguments must be an object")
            return
        tool = self.registry.get(name)
        if tool is None:
            self._error(msg_id, INVALID_PARAMS, f"Unknown tool: {name}")
            return
        try:
            structured, text = tool.call(arguments)
        except ValueError as exc:
            self._tool_error(msg_id, f"Invalid input: {exc}")
            return
        except Exception as exc:  # noqa: BLE001
            logger.exception("Tool %s failed", name)
            self._tool_error(msg_id, f"Tool execution failed: {exc}")
            return
        self._structured_ok(msg_id, structured, text)

    def _dispatch(self, message: dict):
        if message.get("jsonrpc") != "2.0":
            if "id" in message:
                self._error(message.get("id"), INVALID_REQUEST, "Invalid JSON-RPC version")
            return
        method = message.get("method")
        msg_id = message.get("id")
        params = message.get("params") or {}

        if method == "initialize":
            self._handle_initialize(msg_id, params)
            return
        if method == "notifications/initialized":
            self.initialized = True
            return
        if method in ("notifications/cancelled", "notifications/progress"):
            return
        if method is None:
            return
        if msg_id is None:
            return

        if method == "ping":
            self._result(msg_id, {})
        elif method == "tools/list":
            self._result(msg_id, {"tools": self.registry.list()})
        elif method == "tools/call":
            self._handle_tools_call(msg_id, params)
        else:
            self._error(msg_id, METHOD_NOT_FOUND, f"Method not found: {method}")

    def serve(self):
        """Read newline-delimited JSON-RPC messages until EOF."""
        for raw in self.stdin:
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8", errors="replace")
            raw = raw.rstrip("\n")
            if not raw.strip():
                continue
            if len(raw.encode("utf-8", errors="replace")) > MAX_MESSAGE_BYTES:
                self._error(None, INVALID_REQUEST, "Message exceeds size limit")
                continue
            try:
                message = json.loads(raw)
            except ValueError:
                self._error(None, PARSE_ERROR, "Parse error")
                continue
            if isinstance(message, list):
                self._error(None, INVALID_REQUEST, "Batch requests are not supported")
                continue
            if not isinstance(message, dict):
                self._error(None, INVALID_REQUEST, "Request must be a JSON object")
                continue
            try:
                self._dispatch(message)
            except Exception as exc:  # noqa: BLE001
                logger.exception("Dispatch failure")
                if message.get("id") is not None:
                    self._error(message.get("id"), INTERNAL_ERROR, str(exc))


def run(root: Path, stdin=None, stdout=None):
    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    MCPServer(root, stdin=stdin, stdout=stdout).serve()
