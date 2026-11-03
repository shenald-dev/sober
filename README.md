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
[![Zero Bloat](https://img.shields.io/badge/Speed-%3C200ms-ff007f.svg?style=for-the-badge)](https://github.com/shenald-dev/sober)

</div>

---

## 📑 Table of Contents
- [⚡ The Problem: The Vibe Coding Hangover](#-the-problem-the-vibe-coding-hangover)
- [🌟 What is Sober?](#-what-is-sober)
- [🚀 Core Detection Pillars](#-core-detection-pillars)
- [⚡ Quick Start Guide](#-quick-start-guide)
- [💻 CLI Usage & Commands](#-cli-usage--commands)
- [👀 Real-Time Live Watcher (`sober watch`)](#-real-time-live-watcher-sober-watch)
- [🤖 Agent Self-Healing Remediation (`sober explain`)](#-agent-self-healing-remediation-sober-explain)
- [⚙️ Configuration (`sober.toml`)](#️-configuration-sobertoml)
- [🛡️ Native Git Hooks & CI/CD SARIF](#️-native-git-hooks--cicd-sarif)
- [🏗️ Architecture](#️-architecture)
- [🤝 Contributing](#-contributing)

---

## ⚡ The Problem: The Vibe Coding Hangover

You just spent 3 hours vibe-coding with **Claude Code**, **Cursor**, **Windsurf**, or **Copilot**. Your prototype spins up blindingly fast, but you have that familiar, sinking feeling:

- *Did the AI hallucinate a typosquatted package like `reqeusts` or `nummpy` that leaves you vulnerable to slopsquatting supply-chain malware?*
- *Did it invoke `requests.get()` or `fetch()` without a timeout, causing production processes to hang forever on network stalls?*
- *Did it generate authentication tokens using insecure `random.randint()` or `Math.random()`?*
- *Did it directly interpolate untrusted user strings into LLM prompt templates (`f"...{user_msg}..."`), opening prompt injection vulnerabilities?*
- *Did it leave 15 leftover `print(f"DEBUG: ...")`, `console.log("HERE")`, markdown code fences, and `debugger;` statements in production files?*
- *Did it embed conversational assistant comments like `// Certainly! Here is the updated code...` in source files?*
- *Did it silently swallow fatal database errors with `except: pass` or empty `catch {}` blocks?*
- *Did it commit a live OpenAI, Anthropic, Gemini, Groq, Supabase, Stripe, or Hugging Face API key directly into your git history?*
- *Did it disable TLS certificates (`verify=False`) or introduce unsafe deserialization vectors?*
- *Did it re-invent helper functions that already existed in your repository three folders away?*

Standard `git diff` was built for humans reviewing 5-line edits—not humans auditing 500-line multi-file AI rewrites.

**Enter `sober`.**

---

## 🌟 What is Sober?

`sober` is an ultra-fast, zero-config CLI that audits your uncommitted git changes, branches, or entire repositories in **<200ms**. It detects AI-introduced hallucinations, slopsquatting, reliability antipatterns, conversational chatter, slop residue, silent error swallows, duplicate logic, and secret leaks, providing a crystal-clear **Sober Score (0–100%)** before you push to production.

---

## 🚀 Core Detection Pillars

| Pillar | Detection Engine | Severity |
| :--- | :--- | :---: |
| 🧪 **Hallucination & Slopsquatting** | Cross-references new imports against local manifests, live PyPI/npm registries, and Damerau-Levenshtein similarity to popular libraries (e.g. `reqeusts` vs `requests`). | `CRITICAL` |
| 🛡️ **Dangerous AI Antipatterns** | Catches omitted HTTP timeouts (`requests.get`, `fetch`), insecure pseudo-random tokens (`random.choice`), prompt injection vectors (`f"...{user_input}..."`), and client-side system prompt leakage. | `HIGH` / `CRITICAL` |
| 🔑 **Secrets & Leaks** | Catches hardcoded OpenAI, Anthropic, Gemini, Groq, Supabase, Hugging Face, GitHub PATs, AWS, Stripe Live, Pinecone, Slack, Discord, SendGrid, and trivial default passwords. | `CRITICAL` |
| 🛡️ **Vulnerability Vectors** | Detects raw SQL string formatting, `shell=True` command injection, disabled TLS/SSL (`verify=False`), unsafe pickle/YAML deserialization, and trivial JWT secrets. | `HIGH` |
| 👻 **Ghost Code & Error Swallows** | Flags blank `except: pass`, empty `catch {}` blocks, empty promise catches, and dangling `debugger;` breakpoints. | `HIGH` |
| 🤖 **AI Conversational Chatter** | Detects assistant prompt leakage and conversational text (`Certainly! Here is...`, `As an AI language model...`, `Let me know if you need adjustments`). | `LOW` *(Auto-Cureable)* |
| 🧩 **AST Duplication** | Catches AI agents re-inventing existing project helper utilities across files instead of importing them. | `MEDIUM` |
| 🧹 **Debug Debris & Fences** | Finds temporary `print(f"DEBUG...")`, `console.log("here")`, lingering breakpoints, and stray markdown code fences. | `LOW` *(Auto-Cureable)* |

---

## ⚡ Quick Start Guide

### Installation

Install directly via pip from GitHub:

```bash
pip install "git+https://github.com/shenald-dev/sober.git"
```

Or install the pre-built wheel directly from the [latest GitHub Release](https://github.com/shenald-dev/sober/releases/latest):

```bash
pip install https://github.com/shenald-dev/sober/releases/download/v2.0.0/sober-2.0.0-py3-none-any.whl
```

Or run directly with `pipx` or `uv`:

```bash
pipx install "git+https://github.com/shenald-dev/sober.git"
# or
uv tool install "git+https://github.com/shenald-dev/sober.git"
```

---

## 💻 CLI Usage & Commands

### 1. Default Working Tree Audit
Audit your staged and uncommitted git changes instantly:

```bash
sober scan
```

### 2. Air-Gapped Offline Audit (`--offline`)
Perform zero-network audits verifying dependencies strictly against local manifests and disk cache:

```bash
sober scan --offline
```

### 3. Auto-Cure AI Residue & Chatter
Automatically strip leftover debug print statements, console logs, dangling debuggers, stray markdown fences, and AI chatter comments:

```bash
sober scan --cure
# or via standalone cure command:
sober cure
```

### 4. Git Commit Range & PR Branch Auditing (`diff`)
Audit changes introduced across a PR branch or commit range:

```bash
# Audit changes between main and current branch
sober diff main..HEAD

# Audit the last commit
sober diff HEAD~1
```

### 5. Full Repository Scan
Scan all files in the project instead of just git diff changes:

```bash
sober scan --all
```

### 6. Strict Mode (Pre-Commit / CI)
Fails with exit code `1` if your **Sober Score** is below threshold (default: 95%) or if any critical issues are found:

```bash
sober scan --strict
# Custom threshold:
sober scan --strict --min-score 90
```

### 7. GitHub Security SARIF & PR Markdown Export
Generate SARIF 2.1.0 for GitHub Code Scanning or Markdown summary tables for automated PR review comments:

```bash
# Output SARIF format for GitHub Security tab
sober scan --sarif > sober-results.sarif

# Output GitHub Markdown table for PR comments
sober scan --markdown
```

### 8. Native Zero-Dependency Git Hook Manager
Install an automated pre-commit hook directly into `.git/hooks/pre-commit`:

```bash
# Install hook
sober hook install

# Check hook status
sober hook status

# Remove hook
sober hook uninstall
```

### 9. Automated GitHub Actions CI Workflow Setup
Bootstrap `.github/workflows/sober-guard.yml` in one command:

```bash
sober ci init
```

### 10. Project Configuration Initialization
Generate a starter `sober.toml` configuration file:

```bash
sober init
```

---

## 👀 Real-Time Live Watcher (`sober watch`)

Keep a live HUD open alongside your editor while vibe-coding with Cursor, Windsurf, or Claude Code:

```bash
sober watch
# Custom polling interval:
sober watch --interval 0.5
# Auto-cure debris on save:
sober watch --cure
```

Whenever files are saved, `sober` immediately re-audits the project and updates your sobriety score in real-time.

---

## 🤖 Agent Self-Healing Remediation (`sober explain`)

Feed diagnostic audit context directly back to your AI coding agent (Claude Code, Cursor Agent, Copilot Workspace, Aider, Devin):

```bash
sober explain
# Or pipe directly to clipboard / agent:
sober explain | your-agent-fixer
```

Outputs a high-density, zero-hallucination directive containing exact file locations, code snippets, and unambiguous surgical instructions to fix every defect.

---

## ⚙️ Configuration (`sober.toml`)

Configure `sober` on a workspace or project level using `sober.toml` or `pyproject.toml` (`[tool.sober]`):

```toml
# sober.toml (v2.0)
[sober]
min_score = 95.0
fail_on_critical = true
max_workers = 10
offline_mode = false

# Paths to ignore during audits
ignore_paths = [
    "tests/*",
    "docs/*",
    "migrations/*",
]

# Allowed internal or proprietary packages that should never trigger hallucination alerts
allowed_packages = [
    "@my-org/*",
    "internal_company_sdk",
]

# Disable specific detectors if needed
# disabled_detectors = ["duplicates"]

# Custom proprietary secret regex patterns
# [[sober.custom_secret_patterns]]
# name = "Company Internal API Token"
# pattern = "comp_[A-Za-z0-9]{32}"
```

---

## 🛡️ Native Git Hooks & CI/CD SARIF

### Native Pre-Commit Hook

Install `sober` directly into your repository with zero third-party dependencies:

```bash
sober hook install
```

Now, every `git commit` automatically triggers `sober scan --strict`, preventing AI slop or accidental credential leaks from ever entering git history!

### One-Command GitHub Actions CI Generator

```bash
sober ci init
```

Generates `.github/workflows/sober-guard.yml`:

```yaml
name: SOBER Code Sobriety Radar

on:
  pull_request:
    branches: [main, master]
  push:
    branches: [main, master]

jobs:
  sober-audit:
    name: AI Hangover & Security Audit
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install SOBER
        run: pip install git+https://github.com/shenald-dev/sober.git

      - name: Run SOBER Audit (SARIF & Markdown)
        run: |
          sober scan --all --sarif > sober.sarif
          sober scan --all --markdown > sober-summary.md
          cat sober-summary.md >> $GITHUB_STEP_SUMMARY
        continue-on-error: true

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: sober.sarif
          category: sober-hangover-guard

      - name: Strict Sobriety Gate
        run: sober scan --all --strict --min-score 90
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
│  Scanned 18 files in 0.11s.                                                 │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

- **95% – 100%** &rarr; `🧊 Crystal Sober`: Production ready, strictly typed, pristine flow.
- **80% – 94%** &rarr; `☕ Mild Buzz`: Minor debug debris or unaddressed stubs detected.
- **60% – 79%** &rarr; `🍸 Noticeable Hangover`: Review required. High-risk patterns found.
- **< 60%** &rarr; `🚨 Complete Blackout`: Critical security vulnerabilities or hallucinated dependencies. **Do NOT deploy.**

---

## 🏗️ Architecture

```
                    ┌─────────────────────────┐
                    │   Git Workspace / Target│
                    └───────────┬─────────────┘
                                │
                                ▼
                    ┌─────────────────────────┐
                    │  Scanner & Diff Engine  │ (Uncommitted changes,
                    │   (git status & ranges) │  commit diffs, or all)
                    └───────────┬─────────────┘
                                │
               ┌────────────────┼────────────────┐
               ▼                ▼                ▼
    ┌──────────────────────┐ ┌────────────────┐ ┌──────────────────────┐
    │ Manifest Inspector   │ │ Disk Registry  │ │ Config Engine        │
    │ (package.json/pyproj)│ │ Cache (TTL)    │ │ (sober.toml loader)  │
    └──────────┬───────────┘ └───────┬────────┘ └──────────┬───────────┘
               │                     │                     │
               └────────────────┬────┴─────────────────────┘
                                │
                                ▼
                    ┌─────────────────────────┐
                    │ Detection Pillar Pool   │
                    │ • Slopsquatting / PyPI  │
                    │ • Dangerous Antipatterns│
                    │ • Secrets & Webhooks    │
                    │ • AI Chatter & Fences   │
                    │ • Silent Error Swallows │
                    │ • AST Duplication       │
                    └───────────┬─────────────┘
                                │
         ┌──────────────────────┼──────────────────────┐
         ▼                      ▼                      ▼
┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐
│ Sobriety Radar   │   │ Live Vibe Watch  │   │ Agent Remediation│
│ • Terminal HUD   │   │ • File monitor   │   │ • sober explain  │
│ • SARIF 2.1.0    │   │ • Real-time HUD  │   │ • Self-healing   │
│ • Markdown PR    │   │ • Auto-cure      │   │   directive      │
└──────────────────┘   └──────────────────┘   └──────────────────┘
```

---

## 🤝 Contributing

Contributions are welcome! Please open an issue or PR on [GitHub](https://github.com/shenald-dev/sober).

```bash
git clone https://github.com/shenald-dev/sober.git
cd sober
pip install -e ".[dev]"
pytest
ruff check .
```

---

## 📜 License

MIT License. Designed and built with ❤️ by [shenald-dev](https://github.com/shenald-dev).
