"""
Detector for Hallucinated or Slopsquatted dependencies.

Verifies that newly introduced external imports exist in PyPI, npm, local manifests,
or configured whitelists. Registry verification is batched and single-flighted so a
package imported by many files is checked once per run, and disk verdicts are
persisted with a single write.
"""

import ast
import concurrent.futures
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

from sober.core.config import SoberConfig
from sober.core.context import FileContext
from sober.core.manifest import ManifestInspector
from sober.core.registry_cache import global_registry_cache
from sober.core.scanner import FileToAudit
from sober.detectors import Issue, Severity
from sober.detectors.slopsquatting import find_slopsquatted_target

# Authoritative stdlib set on Python 3.10+; small fallback for exotic runtimes.
PYTHON_STDLIB: set[str] = set(getattr(sys, "stdlib_module_names", ())) | {
    "typing_extensions", "__future__",
}

NODE_BUILTINS: set[str] = {
    "assert", "async_hooks", "buffer", "child_process", "cluster", "console",
    "constants", "crypto", "dgram", "diagnostics_channel", "dns", "domain",
    "events", "fs", "fs/promises", "http", "http2", "https", "inspector",
    "module", "net", "os", "path", "path/posix", "path/win32", "perf_hooks",
    "process", "punycode", "querystring", "readline", "repl", "stream",
    "stream/consumers", "stream/promises", "stream/web", "string_decoder",
    "sys", "timers", "timers/promises", "tls", "trace_events", "tty", "url",
    "util", "util/types", "v8", "vm", "wasi", "worker_threads", "zlib",
}

# In-memory registry cache to keep execution under 1 second
_REGISTRY_CACHE: dict[str, bool] = {}


def _http_exists(url: str) -> bool | None:
    """Return True/False for a definitive registry verdict, None when inconclusive."""
    req = urllib.request.Request(url, headers={"User-Agent": "sober-audit-cli"})
    try:
        with urllib.request.urlopen(req, timeout=2.5) as resp:
            return resp.status == 200
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False
        return True
    except (urllib.error.URLError, TimeoutError, OSError):
        return None


def is_pypi_package_real(package_name: str) -> bool:
    """Verify package exists on PyPI with local disk cache acceleration."""
    clean_name = package_name.lower().replace("_", "-")
    if clean_name in _REGISTRY_CACHE:
        return _REGISTRY_CACHE[clean_name]
    cached = global_registry_cache.get(f"pypi:{clean_name}")
    if cached is not None:
        _REGISTRY_CACHE[clean_name] = cached
        return cached
    verdict = _http_exists(f"https://pypi.org/pypi/{clean_name}/json")
    if verdict is None:
        return True
    _REGISTRY_CACHE[clean_name] = verdict
    global_registry_cache.set(f"pypi:{clean_name}", verdict)
    return verdict


def is_npm_package_real(package_name: str) -> bool:
    """Verify package exists on npm registry with local disk cache acceleration."""
    clean_name = package_name.strip()
    if clean_name in _REGISTRY_CACHE:
        return _REGISTRY_CACHE[clean_name]
    cached = global_registry_cache.get(f"npm:{clean_name}")
    if cached is not None:
        _REGISTRY_CACHE[clean_name] = cached
        return cached
    verdict = _http_exists(f"https://registry.npmjs.org/{clean_name}")
    if verdict is None:
        return True
    _REGISTRY_CACHE[clean_name] = verdict
    global_registry_cache.set(f"npm:{clean_name}", verdict)
    return verdict


def extract_python_imports(code: str) -> list[tuple[str, int, str]]:
    """Extract top-level external module imports with their line numbers."""
    imports = []
    try:
        tree = ast.parse(code)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root_pkg = alias.name.split(".")[0]
                    imports.append((root_pkg, node.lineno, f"import {alias.name}"))
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                root_pkg = node.module.split(".")[0]
                imports.append((root_pkg, node.lineno, f"from {node.module} import ..."))
    except (SyntaxError, ValueError):
        for i, line in enumerate(code.splitlines(), start=1):
            line_str = line.strip()
            if line_str.startswith("import "):
                m = re.match(r"import\s+([A-Za-z0-9_]+)", line_str)
                if m:
                    imports.append((m.group(1), i, line_str))
            elif line_str.startswith("from "):
                m = re.match(r"from\s+([A-Za-z0-9_]+)", line_str)
                if m:
                    imports.append((m.group(1), i, line_str))
    return imports


def extract_js_imports(code: str) -> list[tuple[str, int, str]]:
    """Extract imported external npm package names from JS/TS code."""
    imports = []
    for i, line in enumerate(code.splitlines(), start=1):
        line_clean = line.strip()
        m = re.search(r"""import\s+(?:[^'"]+\s+from\s+)?['"]([^'"]+)['"]""", line_clean)
        if m:
            pkg = m.group(1)
            if not pkg.startswith(".") and not pkg.startswith("/"):
                pkg_name = pkg if not pkg.startswith("@") else "/".join(pkg.split("/")[:2])
                if not pkg.startswith("@") and "/" in pkg_name:
                    pkg_name = pkg_name.split("/")[0]
                imports.append((pkg_name, i, line_clean))
        m_req = re.search(r"""require\s*\(\s*['"]([^'"]+)['"]\s*\)""", line_clean)
        if m_req:
            pkg = m_req.group(1)
            if not pkg.startswith(".") and not pkg.startswith("/"):
                pkg_name = pkg if not pkg.startswith("@") else "/".join(pkg.split("/")[:2])
                if not pkg.startswith("@") and "/" in pkg_name:
                    pkg_name = pkg_name.split("/")[0]
                imports.append((pkg_name, i, line_clean))
    return imports


def local_module_names(project_root: Path) -> set[str]:
    """Compute importable local module/package names once per audit."""
    names = {p.stem for p in project_root.glob("*.py")}
    names.update(p.name for p in project_root.iterdir() if p.is_dir())
    src = project_root / "src"
    if src.is_dir():
        names.update(p.name for p in src.iterdir())
    return names


# Candidate: (file_rel, package, lineno, snippet, ecosystem)
Candidate = tuple[str, str, int, str, str]


def collect_candidates(
    ctx: FileContext,
    project_root: Path,
    manifest: ManifestInspector,
    cfg: SoberConfig,
    local_modules: set[str],
) -> tuple[list[Issue], list[Candidate]]:
    """Return immediate slopsquatting issues plus pending registry candidates."""
    file_rel = ctx.rel_path(project_root)
    squat_issues: list[Issue] = []
    pending: list[Candidate] = []
    ext = ctx.extension

    if ext == ".py":
        imports = extract_python_imports(ctx.content)
        ecosystem = "python"
    elif ext in {".js", ".jsx", ".ts", ".tsx"}:
        imports = extract_js_imports(ctx.content)
        ecosystem = "npm"
    else:
        return squat_issues, pending

    for pkg, lineno, snippet in imports:
        if ecosystem == "python":
            if pkg in PYTHON_STDLIB or pkg in local_modules:
                continue
            if manifest.is_declared_python_package(pkg) or cfg.is_package_whitelisted(pkg):
                continue
        else:
            if pkg in NODE_BUILTINS or pkg.startswith("node:"):
                continue
            if manifest.is_declared_js_package(pkg) or cfg.is_package_whitelisted(pkg):
                continue
        if not ctx.in_diff(lineno):
            continue

        squat_target, dist = find_slopsquatted_target(pkg, ecosystem=ecosystem)
        if squat_target:
            label = "PyPI" if ecosystem == "python" else "npm"
            squat_issues.append(
                Issue(
                    category="Slopsquatting Risk",
                    title=f"Suspicious dependency '{pkg}' resembles '{squat_target}'",
                    description=(
                        f"Imported {label} package '{pkg}' has a distance of {dist} from popular "
                        f"library '{squat_target}'. AI often hallucinates typosquatted package names, "
                        "exposing projects to supply-chain malware."
                    ),
                    severity=Severity.CRITICAL,
                    file_path=file_rel,
                    line_number=lineno,
                    code_snippet=snippet,
                    fix_suggestion=f"Did you mean '{squat_target}'? Change import to '{squat_target}' or declare in manifests.",
                    rule_id="SOBER-HAL002",
                )
            )
            continue

        if not cfg.offline_mode:
            pending.append((file_rel, pkg, lineno, snippet, ecosystem))

    return squat_issues, pending


def verify_packages(pending: list[Candidate], cfg: SoberConfig) -> dict[tuple[str, str], bool]:
    """Single-flight, batched registry verification across all pending candidates."""
    unique: dict[tuple[str, str], str] = {}
    for _file_rel, pkg, _lineno, _snippet, ecosystem in pending:
        key = (ecosystem, pkg)
        if key not in unique:
            unique[key] = pkg.lower().replace("_", "-") if ecosystem == "python" else pkg.strip()

    verdicts: dict[tuple[str, str], bool] = {}
    to_fetch: list[tuple[tuple[str, str], str]] = []
    for key, clean in unique.items():
        if clean in _REGISTRY_CACHE:
            verdicts[key] = _REGISTRY_CACHE[clean]
            continue
        cached = global_registry_cache.get(f"{key[0]}:{clean}")
        if cached is not None:
            _REGISTRY_CACHE[clean] = cached
            verdicts[key] = cached
        else:
            to_fetch.append((key, clean))

    if to_fetch:
        workers = max(1, min(cfg.max_workers, len(to_fetch)))
        disk_updates: dict[str, bool] = {}

        def fetch(item):
            key, clean = item
            url = (f"https://pypi.org/pypi/{clean}/json" if key[0] == "python"
                   else f"https://registry.npmjs.org/{clean}")
            return key, clean, _http_exists(url)

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            for key, clean, verdict in executor.map(fetch, to_fetch):
                if verdict is None:
                    verdicts[key] = True  # inconclusive network -> do not block
                    continue
                verdicts[key] = verdict
                _REGISTRY_CACHE[clean] = verdict
                disk_updates[f"{key[0]}:{clean}"] = verdict
        global_registry_cache.set_many(disk_updates)

    return verdicts


def emit_issues(pending: list[Candidate], verdicts: dict[tuple[str, str], bool]) -> list[Issue]:
    issues = []
    for file_rel, pkg, lineno, snippet, ecosystem in pending:
        if verdicts.get((ecosystem, pkg), True):
            continue
        if ecosystem == "python":
            title = f"Non-existent PyPI package '{pkg}'"
            desc = (f"Package '{pkg}' was imported by AI but does not exist on PyPI or local "
                    "manifests (potential hallucination or slopsquatting risk).")
            fix = f"Remove '{pkg}', install the real package, or add to allowed_packages in sober.toml."
        else:
            title = f"Non-existent npm package '{pkg}'"
            desc = (f"Package '{pkg}' was imported by AI but does not exist on npm registry or "
                    "package.json (slopsquatting vulnerability).")
            fix = f"Install the real package or add '{pkg}' to allowed_packages in sober.toml."
        issues.append(
            Issue(
                category="Hallucinated Dependency",
                title=title,
                description=desc,
                severity=Severity.CRITICAL,
                file_path=file_rel,
                line_number=lineno,
                code_snippet=snippet,
                fix_suggestion=fix,
                rule_id="SOBER-HAL001",
            )
        )
    return issues


def audit_hallucinations(
    file_audit: FileToAudit,
    project_root: Path,
    manifest_inspector: ManifestInspector | None = None,
    config: SoberConfig | None = None,
    ctx: FileContext | None = None,
    local_modules: set[str] | None = None,
) -> list[Issue]:
    """Scan file for hallucinated or non-existent external dependencies."""
    ctx = ctx or FileContext(file_audit)
    if not ctx.content:
        return []
    manifest = manifest_inspector or ManifestInspector(project_root)
    cfg = config or SoberConfig()
    modules = local_modules if local_modules is not None else local_module_names(project_root)
    squat_issues, pending = collect_candidates(ctx, project_root, manifest, cfg, modules)
    verdicts = verify_packages(pending, cfg)
    return squat_issues + emit_issues(pending, verdicts)
