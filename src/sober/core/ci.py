"""
CI / GitHub Actions Workflow Generator for SOBER.
Bootstraps ready-to-run GitHub Actions workflows for automated PR sobriety checks.
"""

from pathlib import Path

GITHUB_ACTIONS_WORKFLOW = """name: SOBER Code Sobriety Radar

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
        run: |
          pip install git+https://github.com/shenald-dev/sober.git

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
        run: |
          sober scan --all --strict --min-score 90
"""


def init_github_actions_workflow(repo_root: Path) -> Path:
    """Create .github/workflows/sober-guard.yml."""
    workflows_dir = repo_root / ".github" / "workflows"
    workflows_dir.mkdir(parents=True, exist_ok=True)
    workflow_file = workflows_dir / "sober-guard.yml"
    workflow_file.write_text(GITHUB_ACTIONS_WORKFLOW, encoding="utf-8")
    return workflow_file
