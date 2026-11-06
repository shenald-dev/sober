# Changelog

All notable changes to `sober` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]
- **[Fixed]:** Suppress `vulture` dead-code false positives on Typer commands by configuring `ignore_names` in `pyproject.toml` to ignore the prepended underscores.
- **[Fixed]:** Repaired Git diff parsing mechanisms in `sober.core.scanner` and `sober.core.git_helper` to correctly parse and handle modifications on paths with spaces or quotation marks.
- **[Fixed]:** Addressed a bug preventing proper installation of pre-commit hooks in Git worktrees by resolving relative `gitdir:` paths correctly against the worktree root.
- **[Fixed]:** Added robust logging to graceful exception fallbacks to prevent silent failures.
- **[Pruned]:** Removed unused `PY_HTTP_CALL_REGEX` variable from `sober.detectors.antipatterns` and renamed Typer CLI functions for strict dead code elimination.

## [2.0.0] - 2026-11-03

### 🚀 Major v2.0 Flagship Production Release

#### Added
- **Dangerous AI Code Patterns Engine (`sober.detectors.antipatterns`)**:
  - Detection of omitted HTTP request timeouts (`requests.get/post`, `httpx.get/post`, `fetch()`) preventing catastrophic production process hangs (`HIGH`).
  - Detection of insecure pseudo-random generation (`random.randint`, `random.choice`, `Math.random`) used for security tokens and secret keys (`HIGH`).
  - Detection of direct unescaped/unvalidated string interpolation into LLM prompt templates (`f"...{user_input}..."`), preventing prompt injection and jailbreaks (`CRITICAL`).
  - Detection of confidential internal system instructions and persona prompts embedded in client-side code (`.js/.ts`) (`HIGH`).
- **Slopsquatting & Typosquatting Defense Engine (`sober.detectors.slopsquatting`)**:
  - Damerau-Levenshtein distance calculation comparing imported dependencies against the top 100 most popular Python and npm packages.
  - Instantly flags typosquatted hallucinated package names (e.g. `reqeusts` vs `requests`, `nummpy` vs `numpy`, `axois` vs `axios`) to defend against AI supply-chain injection attacks (`CRITICAL`).
- **Air-Gapped Offline Mode (`sober scan --offline`, `offline_mode = true`)**:
  - Allows zero-network local audits verifying imports exclusively against local manifests, standard library, and local disk cache without network latency or external queries.
- **Live Vibe-Coding Watcher Daemon (`sober watch`)**:
  - Sub-second filesystem monitoring daemon designed for real-time pair programming with Cursor, Windsurf, Claude Code, and Copilot.
  - Automatically re-audits code upon save and renders a persistent live sobriety dashboard with current Sober Score.
- **AI Agent Self-Healing Remediation Context (`sober explain` / `sober prompt`)**:
  - High-density, zero-hallucination markdown prompt generator tailored to feed audit results directly back into LLM coding agents (Cursor, Claude Code, Aider, Devin).
- **Expanded Modern Secret & Key Detection**:
  - Added detection patterns for Groq (`gsk_...`), Supabase (`sbp_...`), SendGrid (`SG....`), Slack Incoming Webhooks, Discord Webhooks, and hardcoded trivial default passwords (`password = "admin"`).
- **Automated GitHub Actions CI Generator (`sober ci init`)**:
  - One-command bootstrapping of `.github/workflows/sober-guard.yml` configured to upload SARIF 2.1.0 to GitHub Code Scanning Alerts and enforce PR sobriety gates.
- **Enhanced Auto-Cure Engine (`sober cure` / `--cure`)**:
  - Strips stray markdown code fences (``` or ```python) accidentally copy-pasted into source code files.
- **Comprehensive v2.0.0 Test Suite**:
  - Added 28 new unit and integration tests across antipatterns, slopsquatting, live watcher, remediation prompt generator, and CLI v2 workflows (80 tests passing, 84% coverage).

#### Changed
- Promoted package version to `2.0.0`.
- Updated starter `sober.toml` config to include `offline_mode` and new detector documentation.

---

## [1.0.0] - 2026-11-02

### 🚀 Major v1.0 Production Release

#### Added
- **AI Conversational Chatter & Prompt Leakage Detector (`sober.detectors.chatter`)**: Detects and sanitizes assistant artifacts (`Certainly! Here is...`, `As an AI language model...`, `Let me know if you need any adjustments`, placeholder comments).
- **Git Revision Range Auditing (`sober diff [REVISION]`)**: Audit PR branches and commit ranges (e.g. `sober diff main..HEAD`, `sober diff HEAD~1`).
- **Native Zero-Dependency Git Hook Manager (`sober hook install / uninstall / status`)**: One-command installation of `.git/hooks/pre-commit` to prevent committing AI slop and secrets without requiring external dependencies.
- **SARIF 2.1.0 Export (`sober scan --sarif`)**: Native integration with GitHub Code Scanning Security tab.
- **Markdown PR Comment Export (`sober scan --markdown`)**: Generates formatted GitHub Flavored Markdown summary tables for automated CI PR review bots.
- **Declarative Configuration Engine (`sober init`, `sober.toml`, `pyproject.toml [tool.sober]`)**: Support for workspace-level `min_score`, `allowed_packages`, `ignore_paths`, `disabled_detectors`, and custom secret patterns.
- **Local Manifest Cross-Referencing (`sober.core.manifest`)**: Whitelists dependencies declared in `package.json`, `requirements.txt`, `pyproject.toml`, and `Pipfile` before hitting network.
- **Persistent Disk Registry Cache (`sober.core.registry_cache`)**: Thread-safe on-disk cache with TTL for PyPI and npm registries (`~/.cache/sober/registry_cache.json`), delivering sub-150ms repeat audits.
- **Expanded AI & Cloud Secret Detection**: Added detection patterns for Google Gemini, Hugging Face, Stripe Live, Pinecone, Slack, Replicate, and Resend API tokens.
- **Advanced Security Vectors**: Added checks for disabled TLS/SSL certificates (`verify=False`, `rejectUnauthorized: false`), unsafe pickle and YAML deserialization, and trivial JWT secrets.
- **Standalone Sanitizer Tool (`sober cure`)**: One-shot code sanitization stripping debug debris, dangling debuggers, and AI chatter comments.

#### Fixed & Optimized
- Replaced bare `except: pass` fallbacks across internal modules to guarantee self-audit crystal sobriety (`Score: 100% [A+]`).
- Fixed import order lint violations (`E402`) in test files.
- Expanded automated test coverage across all detectors, config, manifests, registry cache, git ranges, and CLI commands (52 tests passing).

#### Removed
- Removed legacy bot tracking files (`.jules/`) and added tracking artifacts to `.gitignore`.

---

## [0.1.0] - 2026-10-26

### 🚀 Initial Launch: The Vibe Coding Hangover Cure
- **Multi-Vector AI Slop Scanner**: Audits uncommitted git working tree in `<500ms`.
- **Hallucination & Slopsquatting Detector**: Live and cached package validation against PyPI & npm registries.
- **Ghost Code & Debug Debris Purge**: Catches silent exception swallows (`except: pass`, empty `catch {}`), stubs, and leftover `print()` / `console.log()` statements.
- **Security & Secret Leak Guard**: Detects OpenAI, Anthropic, GitHub, and AWS keys, plus command and SQL injection vectors.
- **AST Duplication Detector**: Catches AI-generated helper functions that duplicate existing codebase utilities.
- **Sober Score**: Computes 0–100% sobriety telemetry with health status indicators.
- **Auto-Cure (`--cure`)**: Automatically cleans leftover debug logs and breakpoints.
- **Strict Pre-Commit & CI Mode (`--strict`)**: Seamless integration with Git hooks and GitHub Actions.

