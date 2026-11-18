"""
Per-file audit context.

Reads each file exactly once and lazily shares derived artifacts (source lines,
parsed Python AST, content hash and suppression map) across every detector. This
eliminates the repeated disk reads and repeated ``ast.parse`` calls of the legacy
per-detector pipeline.
"""

from __future__ import annotations

import ast
import hashlib

from sober.core.scanner import FileToAudit
from sober.core.suppress import build_suppression_map


class FileContext:
    __slots__ = (
        "file", "path", "extension", "content", "lines", "diff_lines",
        "_ast", "_ast_done", "_hash", "_suppressions",
    )

    def __init__(self, file_audit: FileToAudit, content: str | None = None):
        self.file = file_audit
        self.path = file_audit.path
        self.extension = file_audit.extension
        self.content = content if content is not None else file_audit.read_text()
        self.lines = self.content.splitlines()
        self.diff_lines = file_audit.diff_lines
        self._ast: ast.AST | None = None
        self._ast_done = False
        self._hash: str | None = None
        self._suppressions: dict | None = None

    @property
    def tree(self) -> ast.AST | None:
        """Parsed Python AST (parsed once; ``None`` for non-Python or syntax errors)."""
        if not self._ast_done:
            self._ast_done = True
            if self.extension == ".py" and self.content:
                try:
                    self._ast = ast.parse(self.content)
                except (SyntaxError, ValueError):
                    self._ast = None
        return self._ast

    @property
    def content_hash(self) -> str:
        if self._hash is None:
            self._hash = hashlib.sha256(
                self.content.encode("utf-8", errors="replace")
            ).hexdigest()
        return self._hash

    @property
    def suppressions(self) -> dict:
        if self._suppressions is None:
            self._suppressions = build_suppression_map(self.lines)
        return self._suppressions

    def in_diff(self, line_number: int) -> bool:
        return not self.diff_lines or line_number in self.diff_lines

    def rel_path(self, root) -> str:
        try:
            return str(self.path.relative_to(root))
        except ValueError:
            return str(self.path)
