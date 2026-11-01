# APEX-BOLT Journal — Sober

## 2026-10-26 — Initial Fast Audit Architecture

- **Learning:** Offline-first heuristic analysis combined with asynchronous thread-pooled registry lookups (PyPI & npm) allows full codebase audit under 400ms without blocking local developer workflow.
- **Action:** Maintain pure local AST parsing and keep online network checks non-blocking with tight 2.5s timeout.

## 2026-11-01 — Robust Git Path Parsing

- **Learning:** `git status` output by default quotes files with spaces and special characters. We must use `-z` (null-terminated) for robust handling of renames/copies, and disable `core.quotepath` when retrieving line diffs to map back to files accurately.
- **Action:** Ensure any future git parsing logic uses zero-byte termination (`-z`) and disables quote paths (`-c core.quotepath=false`).
