# Changelog

All notable changes to `sober` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
