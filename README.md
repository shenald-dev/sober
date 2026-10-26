<div align="center">

```
   ____ ____  ____  _____ ____  
  / ___/ __ \| __ )| ____|  _ \ 
  \___ \ | | |  _ \|  _| | |_) |
   ___) | |_| | |_) | |___|  _ < 
  |____/\____/|____/|_____|_| \_\
```

<h3>🍸 sober</h3>
<p><b>The Vibe Coding Hangover Cure</b></p>
<i>Audit, sanitize, and proofread AI-generated code before pushing to production. Zero bloat. Maximum Flow.</i>

<br/><br/>

[![Release](https://img.shields.io/github/v/release/shenald-dev/sober?color=ff007f&style=for-the-badge&logo=github)](https://github.com/shenald-dev/sober/releases)
[![Python](https://img.shields.io/badge/Python-3.10%2B-00d4ff.svg?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-00e676.svg?style=for-the-badge)](LICENSE)
[![CI Status](https://img.shields.io/badge/CI-Passing-00d4ff.svg?style=for-the-badge&logo=githubactions&logoColor=white)](https://github.com/shenald-dev/sober/actions)
[![Zero Bloat](https://img.shields.io/badge/Speed-%3C500ms-ff007f.svg?style=for-the-badge)](https://github.com/shenald-dev/sober)

</div>

---

## 📑 Table of Contents
- [⚡ The Problem: The Vibe Coding Hangover](#-the-problem-the-vibe-coding-hangover)
- [🌟 What is Sober?](#-what-is-sober)
- [🚀 Core Detection Pillars](#-core-detection-pillars)
- [⚡ Quick Start Guide](#-quick-start-guide)
- [💻 CLI Usage & Commands](#-cli-usage--commands)
- [🛡️ Pre-Commit & CI/CD Integration](#️-pre-commit--cicd-integration)
- [🤝 Contributing](#-contributing)

---

## ⚡ The Problem: The Vibe Coding Hangover

You just spent 3 hours vibe-coding with **Claude Code**, **Cursor**, or **Windsurf**. Your prototype spins up blindingly fast, but you have that familiar, sinking feeling:

- *Did the AI hallucinate a non-existent package that leaves you vulnerable to slopsquatting?*
- *Did it leave 15 leftover `print(f"DEBUG: ...")` and `console.log("HERE")` statements in production files?*
- *Did it silently swallow fatal database errors with `except: pass`?*
- *Did it commit a live OpenAI or Anthropic API key directly into your git history?*
- *Did it re-invent helper functions that already existed in your repo three folders away?*

Standard `git diff` was built for humans reviewing 5-line edits—not humans auditing 500-line multi-file AI rewrites.

**Enter `sober`.**

---

## 🌟 What is Sober?

`sober` is an ultra-fast, zero-config CLI that audits your uncommitted git changes in **<500ms**. It detects AI-introduced hallucinations, slop residue, silent error swallows, duplicate logic, and secret leaks, providing a crystal-clear **Sober Score (0–100%)** before you push to production.

---

## 🚀 Core Detection Pillars

| Pillar | Detection Engine | Severity |
| :--- | :--- | :---: |
| 🧪 **Hallucination & Slopsquatting** | Cross-references new imports against live and cached PyPI/npm registries to catch fabricated libraries. | `CRITICAL` |
| 🔑 **Secrets & Leaks** | Catches hardcoded OpenAI (`sk-...`), Anthropic (`sk-ant-...`), GitHub PATs, and AWS access keys. | `CRITICAL` |
| 🛡️ **Vulnerability Vectors** | Detects raw SQL string formatting and `subprocess.call(..., shell=True)` command injection risks. | `HIGH` |
| 👻 **Ghost Code & Error Swallows** | Flags blank `except: pass` and empty `catch {}` blocks that mask production runtime crashes. | `HIGH` |
| 🧩 **AST Duplication** | Catches AI agents re-inventing existing project helper utilities instead of importing them. | `MEDIUM` |
| 🧹 **Debug Debris** | Finds temporary `print(f"DEBUG...")`, `console.log("here")`, and lingering breakpoints. | `LOW` |

---

## ⚡ Quick Start Guide

### Installation

Install directly via pip from GitHub:

```bash
pip install "git+https://github.com/shenald-dev/sober.git"
```

Or install the pre-built wheel directly from the [latest GitHub Release](https://github.com/shenald-dev/sober/releases/latest):

```bash
pip install https://github.com/shenald-dev/sober/releases/download/v0.1.0/sober-0.1.0-py3-none-any.whl
```

Or run directly with `pipx` or `uv`:

```bash
pipx install "git+https://github.com/shenald-dev/sober.git"
```

---

## 💻 CLI Usage & Commands

### 1. Default Working Tree Audit
Audit your staged and uncommitted git changes instantly:

```bash
sober scan
```

### 2. Auto-Cure AI Residue
Automatically strip leftover debug print statements and console logs in one command:

```bash
sober scan --cure
```

### 3. Full Repository Scan
Scan all files in the project instead of just git diff changes:

```bash
sober scan --all
```

### 4. Strict Mode (Pre-Commit / CI)
Fails with exit code `1` if your **Sober Score** is below 95% or if any critical issues are found:

```bash
sober scan --strict
```

### 5. Programmatic JSON Output
Generate machine-readable JSON for CI/CD pipelines or bot automations:

```bash
sober scan --json
```

---

## 📊 Telemetry & The Sober Score

```
┌─────────────────────── 📊 SOBRIETY HEALTH TELEMETRY ────────────────────────┐
│                                                                             │
│  Sober Score: 100% [A+]                                                     │
│  State: 🧊 Crystal Sober (Production Ready)                                 │
│                                                                             │
│  • Critical Issues: 0    • High: 0    • Medium: 0    • Low (Debris): 0      │
│  • Auto-Fixable with --cure: 0                                              │
│                                                                             │
│  Scanned 13 files in 0.33s.                                                 │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

- **95% – 100%** &rarr; `🧊 Crystal Sober`: Production ready, strictly typed, pristine flow.
- **80% – 94%** &rarr; `☕ Mild Buzz`: Minor debug debris or unaddressed stubs detected.
- **60% – 79%** &rarr; `🍸 Noticeable Hangover`: Review required. High-risk patterns found.
- **< 60%** &rarr; `🚨 Complete Blackout`: Critical security vulnerabilities or hallucinated dependencies. **Do NOT deploy.**

---

## 🛡️ Pre-Commit & CI/CD Integration

Add `sober` to your `.pre-commit-config.yaml` to ensure no AI slop slips into your main branch:

```yaml
repos:
  - repo: https://github.com/shenald-dev/sober
    rev: v0.1.0
    hooks:
      - id: sober
        args: ["--strict"]
```

Or add it as a step in your GitHub Actions workflow:

```yaml
- name: Audit AI Code Quality
  run: |
    pip install sober
    sober scan --strict
```

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!
Feel free to check [issues page](https://github.com/shenald-dev/sober/issues).

---

<div align="center">
  <i>Built with intention. Crafted by a Vibe Coder.</i> 🧘‍♂️✨<br/>
  <b>Zero bloat. Maximum Flow.</b>
</div>
