## 2024-11-02 — Bugfix: Git parsing with special chars
- **Learning:** `git diff` and `git status` output fails for filenames containing spaces, non-ASCII characters, or special characters because of how Git quotes them, breaking file lookups in internal tools.
- **Action:** Always use the `-z` (null-terminated) flag and `core.quotepath=false` in future git CLI automation commands.
