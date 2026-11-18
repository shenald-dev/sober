"""
Inline suppression support.

A trailing comment on the offending line silences findings::

    token = random.randint(0, 9)  # sober: ignore[SOBER-CRY001]
    requests.get(url)             # sober: ignore

``sober: ignore`` with no bracket list suppresses every rule on that line.
Works with ``#`` (Python) and ``//`` or ``/* ... */`` (JS/TS) comments.
"""

from __future__ import annotations

import re

_IGNORE_RE = re.compile(
    r"(?:#|//|/\*)\s*sober:\s*ignore(?:\s*\[([^\]]*)\])?",
    re.IGNORECASE,
)


def parse_line_suppression(line: str) -> tuple[bool, frozenset[str]]:
    """Return (suppressed_all, specific_rule_ids) for a single source line."""
    match = _IGNORE_RE.search(line)
    if not match:
        return False, frozenset()
    raw = match.group(1)
    if raw is None:
        return True, frozenset()
    ids = frozenset(part.strip().upper() for part in raw.split(",") if part.strip())
    return False, ids


def build_suppression_map(lines: list[str]) -> dict[int, tuple[bool, frozenset[str]]]:
    """Map 1-based line numbers to their suppression directive (only suppressed lines)."""
    result: dict[int, tuple[bool, frozenset[str]]] = {}
    for idx, line in enumerate(lines, start=1):
        if "sober:" not in line.lower():
            continue
        suppressed_all, ids = parse_line_suppression(line)
        if suppressed_all or ids:
            result[idx] = (suppressed_all, ids)
    return result


def is_suppressed(rule_id: str, line_number: int,
                  suppression_map: dict[int, tuple[bool, frozenset[str]]]) -> bool:
    entry = suppression_map.get(line_number)
    if not entry:
        return False
    suppressed_all, ids = entry
    if suppressed_all:
        return True
    return bool(rule_id) and rule_id.upper() in ids
