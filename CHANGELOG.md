# Changelog

All notable changes to `sober` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
