## 2024-11-02 — Bugfix: Git parsing with special chars
- **Learning:** `git diff` and `git status` output fails for filenames containing spaces, non-ASCII characters, or special characters because of how Git quotes them, breaking file lookups in internal tools.
- **Action:** Always use the `-z` (null-terminated) flag and `core.quotepath=false` in future git CLI automation commands.

## 2024-11-04 — Bugfix: Git diff path parsing
- **Learning:** `core.quotepath=false` only handles Unicode/non-ASCII escaping. Git still surrounds file paths containing spaces or quotes with double quotes (`"b/\"quotes\".py"`) when producing unified diffs. Also, relative `gitdir:` pointers must be resolved against the `.git` file's location, not the current working directory.
- **Action:** Any manual string parsing of `git diff` outputs must check for and strip surrounding quotes, replacing `\"` with `"` and `\\` with `\`.

## 2024-11-07 — Bugfix: Ruff Linting Violations
- **Learning:** Widespread usage of root logger `logging.debug` and nested conditionals flagged by `ruff check` in multiple modules. Typer default argument functions were falsely flagged by `bugbear`.
- **Action:** Future developments must initialize module-level loggers (`logger = logging.getLogger(__name__)`) immediately following all imports, ensure `if` statements are combined where logically identical using `and`, and use `extend-immutable-calls` for `typer.Argument`/`typer.Option` in `pyproject.toml` configurations.
