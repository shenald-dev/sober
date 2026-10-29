"""
Detector for Hallucinated or Slopsquatted dependencies.
Verifies that newly introduced external imports actually exist in PyPI or npm.
"""

import ast
import re
import urllib.error
import urllib.request
from pathlib import Path

from sober.core.scanner import FileToAudit
from sober.detectors import Issue, Severity

# Standard library module sets to prevent false alarms
PYTHON_STDLIB: set[str] = {
    "abc", "aifc", "argparse", "array", "ast", "asynchat", "asyncio", "asyncore",
    "atexit", "audioop", "base64", "bdb", "binascii", "binhex", "bisect", "builtins",
    "bz2", "calendar", "cgi", "cgitb", "chunk", "cmath", "cmd", "code", "codecs",
    "codeop", "collections", "colorsys", "compileall", "concurrent", "configparser",
    "contextlib", "contextvars", "copy", "copyreg", "cProfile", "crypt", "csv",
    "ctypes", "curses", "dataclasses", "datetime", "dbm", "decimal", "difflib",
    "dis", "distutils", "doctest", "email", "encodings", "ensurepip", "enum",
    "errno", "faulthandler", "fcntl", "filecmp", "fileinput", "fnmatch", "fractions",
    "ftplib", "functools", "gc", "getopt", "getpass", "gettext", "glob", "graphlib",
    "gzip", "hashlib", "heapq", "hmac", "html", "http", "imaplib", "imghdr", "imp",
    "importlib", "inspect", "io", "ipaddress", "itertools", "json", "keyword",
    "lib2to3", "linecache", "locale", "logging", "lzma", "mailbox", "mailcap",
    "marshal", "math", "mimetypes", "mmap", "modulefinder", "msilib", "msvcrt",
    "multiprocessing", "netrc", "nntplib", "numbers", "operator", "optparse",
    "os", "ossaudiodev", "parser", "pathlib", "pdb", "pickle", "pickletools",
    "pipes", "pkgutil", "platform", "plistlib", "poplib", "posix", "posixpath",
    "pprint", "profile", "pstats", "pty", "pwd", "py_compile", "pyclbr", "pydoc",
    "queue", "quopri", "random", "re", "readline", "reprlib", "resource", "rlcompleter",
    "runpy", "sched", "secrets", "select", "selectors", "shelve", "shlex", "shutil",
    "signal", "site", "smtpd", "smtplib", "sndhdr", "socket", "socketserver",
    "spwd", "sqlite3", "ssl", "stat", "statistics", "string", "stringprep",
    "struct", "subprocess", "sunau", "symbol", "symtable", "sys", "sysconfig",
    "syslog", "tabnanny", "tarfile", "telnetlib", "tempfile", "termios", "test",
    "textwrap", "threading", "time", "timeit", "tkinter", "token", "tokenize",
    "tomllib", "trace", "traceback", "tracemalloc", "tty", "turtle", "turtledemo",
    "types", "typing", "unicodedata", "unittest", "urllib", "uu", "uuid", "venv",
    "warnings", "wave", "weakref", "webbrowser", "winreg", "winsound", "wsgiref",
    "xdrlib", "xml", "xmlrpc", "zipapp", "zipfile", "zipimport", "zlib", "zoneinfo"
}

NODE_BUILTINS: set[str] = {
    "assert", "async_hooks", "buffer", "child_process", "cluster", "console",
    "constants", "crypto", "dgram", "diagnostics_channel", "dns", "domain",
    "events", "fs", "fs/promises", "http", "http2", "https", "inspector",
    "module", "net", "os", "path", "path/posix", "path/win32", "perf_hooks",
    "process", "punycode", "querystring", "readline", "repl", "stream",
    "stream/consumers", "stream/promises", "stream/web", "string_decoder",
    "sys", "timers", "timers/promises", "tls", "trace_events", "tty", "url",
    "util", "util/types", "v8", "vm", "wasi", "worker_threads", "zlib"
}

# In-memory registry cache to keep execution under 1 second
_REGISTRY_CACHE = {}


def is_pypi_package_real(package_name: str) -> bool:
    """Verify package exists on PyPI."""
    clean_name = package_name.lower().replace("_", "-")
    if clean_name in _REGISTRY_CACHE:
        return _REGISTRY_CACHE[clean_name]

    url = f"https://pypi.org/pypi/{clean_name}/json"
    req = urllib.request.Request(url, headers={"User-Agent": "sober-audit-cli"})
    try:
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            is_valid = resp.status == 200
            _REGISTRY_CACHE[clean_name] = is_valid
            return is_valid
    except urllib.error.HTTPError as e:
        if e.code == 404:
            _REGISTRY_CACHE[clean_name] = False
            return False
        _REGISTRY_CACHE[clean_name] = True
        return True
    except (urllib.error.URLError, TimeoutError, OSError):
        # Network timeout or offline - assume true to prevent blocking unless confirmed 404
        return True


def is_npm_package_real(package_name: str) -> bool:
    """Verify package exists on npm registry."""
    clean_name = package_name.strip()
    if clean_name in _REGISTRY_CACHE:
        return _REGISTRY_CACHE[clean_name]

    url = f"https://registry.npmjs.org/{clean_name}"
    req = urllib.request.Request(url, headers={"User-Agent": "sober-audit-cli"})
    try:
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            is_valid = resp.status == 200
            _REGISTRY_CACHE[clean_name] = is_valid
            return is_valid
    except urllib.error.HTTPError as e:
        if e.code == 404:
            _REGISTRY_CACHE[clean_name] = False
            return False
        _REGISTRY_CACHE[clean_name] = True
        return True
    except (urllib.error.URLError, TimeoutError, OSError):
        return True


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
    except SyntaxError:
        # Fallback to regex if file has partial syntax during audit
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
    lines = code.splitlines()
    for i, line in enumerate(lines, start=1):
        line_clean = line.strip()
        # import ... from "pkg"
        m = re.search(r'''import\s+(?:[^'"]+\s+from\s+)?['"]([^'"]+)['"]''', line_clean)
        if m:
            pkg = m.group(1)
            if not pkg.startswith(".") and not pkg.startswith("/"):
                pkg_name = pkg if not pkg.startswith("@") else "/".join(pkg.split("/")[:2])
                if not pkg.startswith("@") and "/" in pkg_name:
                    pkg_name = pkg_name.split("/")[0]
                imports.append((pkg_name, i, line_clean))
        # require("pkg")
        m_req = re.search(r'''require\s*\(\s*['"]([^'"]+)['"]\s*\)''', line_clean)
        if m_req:
            pkg = m_req.group(1)
            if not pkg.startswith(".") and not pkg.startswith("/"):
                pkg_name = pkg if not pkg.startswith("@") else "/".join(pkg.split("/")[:2])
                if not pkg.startswith("@") and "/" in pkg_name:
                    pkg_name = pkg_name.split("/")[0]
                imports.append((pkg_name, i, line_clean))
    return imports


def audit_hallucinations(file_audit: FileToAudit, project_root: Path) -> list[Issue]:
    """Scan file for hallucinated or non-existent external dependencies."""
    issues = []
    code = file_audit.read_text()
    if not code:
        return issues

    ext = file_audit.extension
    file_rel = str(file_audit.path.relative_to(project_root) if file_audit.path.is_relative_to(project_root) else file_audit.path)

    # 1. Python Audits
    if ext == ".py":
        imports = extract_python_imports(code)
        # Check against local folders/modules in project
        local_modules = {p.name.replace(".py", "") for p in project_root.glob("*.py")}
        local_modules.update({p.name for p in project_root.iterdir() if p.is_dir()})
        if (project_root / "src").is_dir():
            local_modules.update({p.name for p in (project_root / "src").iterdir()})

        for pkg, lineno, snippet in imports:
            if pkg in PYTHON_STDLIB or pkg in local_modules:
                continue

            # If scoped to diff and line is not modified, skip
            if file_audit.diff_lines and lineno not in file_audit.diff_lines:
                continue

            if not is_pypi_package_real(pkg):
                issues.append(
                    Issue(
                        category="Hallucinated Dependency",
                        title=f"Non-existent PyPI package '{pkg}'",
                        description=f"Package '{pkg}' was imported by AI but does not exist on PyPI (potential hallucination or slopsquatting risk).",
                        severity=Severity.CRITICAL,
                        file_path=file_rel,
                        line_number=lineno,
                        code_snippet=snippet,
                        fix_suggestion=f"Remove '{pkg}' or verify the correct library name in requirements.txt.",
                    )
                )

    # 2. JavaScript / TypeScript Audits
    elif ext in {".js", ".jsx", ".ts", ".tsx"}:
        imports = extract_js_imports(code)
        for pkg, lineno, snippet in imports:
            if pkg in NODE_BUILTINS or pkg.startswith("node:"):
                continue

            if file_audit.diff_lines and lineno not in file_audit.diff_lines:
                continue

            if not is_npm_package_real(pkg):
                issues.append(
                    Issue(
                        category="Hallucinated Dependency",
                        title=f"Non-existent npm package '{pkg}'",
                        description=f"Package '{pkg}' was imported by AI but does not exist on npm registry (slopsquatting vulnerability).",
                        severity=Severity.CRITICAL,
                        file_path=file_rel,
                        line_number=lineno,
                        code_snippet=snippet,
                        fix_suggestion="Install the real package or check for typos in package.json.",
                    )
                )

    return issues
