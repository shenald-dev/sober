"""
SOBER audit engine (v3).

Orchestrates a single-read, shared-AST pipeline: per-file detectors run in a bounded
thread pool, registry verification is batched and single-flighted across the whole
run, deterministic findings are served from an incremental content-hash cache, and
inline suppressions are applied last. The legacy per-detector re-read/re-parse hot
path is eliminated.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import time
from pathlib import Path

from sober.core.cache import AuditCache
from sober.core.config import SoberConfig, load_config
from sober.core.context import FileContext
from sober.core.manifest import ManifestInspector
from sober.core.scanner import FileToAudit
from sober.core.scorer import SoberAuditReport
from sober.core.suppress import is_suppressed
from sober.detectors import Issue
from sober.detectors.antipatterns import audit_antipatterns
from sober.detectors.chatter import audit_chatter
from sober.detectors.duplicates import audit_duplicates
from sober.detectors.ghost_code import audit_ghost_code
from sober.detectors.hallucinations import (
    collect_candidates,
    emit_issues,
    local_module_names,
    verify_packages,
)
from sober.detectors.security import audit_security

ENGINE_VERSION = "3"

_FILE_DETECTORS = ("antipatterns", "ghost_code", "security", "chatter")


def config_fingerprint(cfg: SoberConfig, enabled: tuple[str, ...]) -> str:
    payload = {
        "engine": ENGINE_VERSION,
        "enabled": sorted(enabled),
        "custom_secret_patterns": cfg.custom_secret_patterns,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()[:16]


class AuditEngine:
    def __init__(self, root: Path, config: SoberConfig | None = None,
                 offline: bool = False, use_cache: bool = True):
        self.root = root
        self.config = config or load_config(root)
        if offline:
            self.config.offline_mode = True
        self.manifest = ManifestInspector(root)
        self.manifest.inspect()
        self.local_modules = local_module_names(root)
        self.cache = AuditCache(root, enabled=use_cache and self.config.cache_enabled)

    def _enabled(self, name: str) -> bool:
        return self.config.is_detector_enabled(name)

    def _scan_file(self, ctx: FileContext, cfg_key: str):
        """Run deterministic per-file detectors; return (issues, candidates, squats)."""
        cached = None
        if not ctx.diff_lines:
            cached = self.cache.get(ctx.content_hash, cfg_key)
        if cached is not None:
            det_issues = cached
        else:
            det_issues = []
            if self._enabled("antipatterns"):
                det_issues.extend(audit_antipatterns(ctx.file, self.root, ctx=ctx))
            if self._enabled("ghost_code"):
                det_issues.extend(audit_ghost_code(ctx.file, self.root, ctx=ctx))
            if self._enabled("security"):
                det_issues.extend(audit_security(
                    ctx.file, self.root,
                    custom_secret_patterns=self.config.custom_secret_patterns, ctx=ctx))
            if self._enabled("chatter"):
                det_issues.extend(audit_chatter(ctx.file, self.root, ctx=ctx))
            if not ctx.diff_lines:
                self.cache.put(ctx.content_hash, cfg_key, det_issues)

        candidates, squats = [], []
        if self._enabled("hallucinations"):
            squats, candidates = collect_candidates(
                ctx, self.root, self.manifest, self.config, self.local_modules)
        return det_issues, candidates, squats

    def audit(self, files: list[FileToAudit],
              contents: dict[Path, str] | None = None) -> SoberAuditReport:
        start = time.time()
        cfg = self.config
        enabled = tuple(d for d in (*_FILE_DETECTORS, "hallucinations", "duplicates")
                        if self._enabled(d))
        cfg_key = config_fingerprint(cfg, enabled)

        contexts: dict[Path, FileContext] = {}
        for f in files:
            rel = str(f.path.relative_to(self.root)) if f.path.is_relative_to(self.root) else str(f.path)
            if cfg.is_path_ignored(rel):
                continue
            override = (contents or {}).get(f.path)
            contexts[f.path] = FileContext(f, content=override)

        ctx_list = list(contexts.values())
        det_issues: list[Issue] = []
        all_candidates = []
        squat_issues: list[Issue] = []

        workers = max(1, min(cfg.max_workers, len(ctx_list))) if ctx_list else 1
        if ctx_list:
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                futures = [executor.submit(self._scan_file, ctx, cfg_key) for ctx in ctx_list]
                for future in concurrent.futures.as_completed(futures):
                    issues, candidates, squats = future.result()
                    det_issues.extend(issues)
                    all_candidates.extend(candidates)
                    squat_issues.extend(squats)

        hal_issues = []
        if all_candidates:
            verdicts = verify_packages(all_candidates, cfg)
            hal_issues = emit_issues(all_candidates, verdicts)

        dup_issues = []
        if self._enabled("duplicates") and ctx_list:
            dup_issues = audit_duplicates([c.file for c in ctx_list], self.root, contexts=contexts)

        combined = det_issues + hal_issues + squat_issues + dup_issues

        kept: list[Issue] = []
        suppressed = 0
        for issue in combined:
            ctx = contexts.get(self.root / issue.file_path)
            smap = ctx.suppressions if ctx else {}
            if is_suppressed(issue.rule_id, issue.line_number, smap):
                suppressed += 1
            else:
                kept.append(issue)

        kept.sort(key=lambda i: (i.file_path, i.line_number, i.rule_id))
        self.cache.flush()
        duration = time.time() - start
        report = SoberAuditReport(kept, files_scanned=len(ctx_list), duration_seconds=duration)
        report.suppressed_count = suppressed
        report.cache_hits = self.cache.hits
        report.cache_misses = self.cache.misses
        return report
