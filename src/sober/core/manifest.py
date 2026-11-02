"""
Local project manifest analyzer - extracts declared dependencies from package.json,
requirements.txt, pyproject.toml, Pipfile, etc., to avoid redundant network verification.
"""

import json
import re
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore


class ManifestInspector:
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self._python_packages: set[str] = set()
        self._js_packages: set[str] = set()
        self._inspected = False

    def inspect(self):
        """Scan project root for dependency manifests and extract package names."""
        if self._inspected:
            return
        self._inspected = True

        # 1. Parse pyproject.toml
        pyproject = self.project_root / "pyproject.toml"
        if pyproject.is_file():
            try:
                data = tomllib.loads(pyproject.read_bytes().decode("utf-8", errors="replace"))
                # project.dependencies
                for dep in data.get("project", {}).get("dependencies", []):
                    pkg = self._clean_python_req(dep)
                    if pkg:
                        self._python_packages.add(pkg)
                # project.optional-dependencies
                for group in data.get("project", {}).get("optional-dependencies", {}).values():
                    for dep in group:
                        pkg = self._clean_python_req(dep)
                        if pkg:
                            self._python_packages.add(pkg)
                # tool.poetry.dependencies
                for dep in data.get("tool", {}).get("poetry", {}).get("dependencies", {}).keys():
                    self._python_packages.add(dep.lower().replace("_", "-"))
            except (OSError, tomllib.TOMLDecodeError):
                self._python_packages.update([])

        # 2. Parse requirements.txt and requirements-*.txt
        for req_file in self.project_root.glob("*requirement*.txt"):
            if req_file.is_file():
                try:
                    for line in req_file.read_text(encoding="utf-8", errors="replace").splitlines():
                        pkg = self._clean_python_req(line)
                        if pkg:
                            self._python_packages.add(pkg)
                except OSError:
                    continue

        # 3. Parse Pipfile
        pipfile = self.project_root / "Pipfile"
        if pipfile.is_file():
            try:
                data = tomllib.loads(pipfile.read_bytes().decode("utf-8", errors="replace"))
                for section in ["packages", "dev-packages"]:
                    for pkg in data.get(section, {}).keys():
                        self._python_packages.add(pkg.lower().replace("_", "-"))
            except (OSError, tomllib.TOMLDecodeError):
                self._python_packages.update([])

        # 4. Parse package.json
        pkg_json = self.project_root / "package.json"
        if pkg_json.is_file():
            try:
                data = json.loads(pkg_json.read_text(encoding="utf-8", errors="replace"))
                for dep_type in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]:
                    for pkg in data.get(dep_type, {}).keys():
                        self._js_packages.add(pkg)
            except (OSError, json.JSONDecodeError):
                self._js_packages.update([])

    @staticmethod
    def _clean_python_req(req: str) -> str | None:
        """Strip version specifiers, comments, and environment markers from requirement string."""
        line = req.strip()
        if not line or line.startswith(("#", "-", "@", "git+")):
            return None
        # Remove comments
        line = line.split("#")[0].strip()
        # Split operators: ==, >=, <=, ~=, !=, <, >, ;, [
        m = re.split(r"[><=~!;\[]", line)
        if m and m[0].strip():
            return m[0].strip().lower().replace("_", "-")
        return None

    def is_declared_python_package(self, package_name: str) -> bool:
        """Check if Python package is declared in local manifests."""
        self.inspect()
        clean = package_name.lower().replace("_", "-")
        return clean in self._python_packages

    def is_declared_js_package(self, package_name: str) -> bool:
        """Check if JS/TS package is declared in package.json."""
        self.inspect()
        return package_name in self._js_packages
