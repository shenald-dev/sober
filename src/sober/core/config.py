"""
Configuration loader for SOBER - supports sober.toml and pyproject.toml [tool.sober].
"""

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore


@dataclass
class SoberConfig:
    min_score: float = 95.0
    fail_on_critical: bool = True
    ignore_paths: list[str] = field(default_factory=list)
    allowed_packages: list[str] = field(default_factory=list)
    disabled_detectors: list[str] = field(default_factory=list)
    custom_secret_patterns: list[dict[str, str]] = field(default_factory=list)
    max_workers: int = 10

    def is_path_ignored(self, rel_path: str) -> bool:
        """Check if relative file path matches any ignore glob patterns."""
        normalized = rel_path.replace("\\", "/")
        for pattern in self.ignore_paths:
            norm_pattern = pattern.replace("\\", "/")
            if fnmatch.fnmatch(normalized, norm_pattern) or fnmatch.fnmatch(Path(normalized).name, norm_pattern):
                return True
        return False

    def is_package_whitelisted(self, package_name: str) -> bool:
        """Check if package name matches any allowed package names or wildcard scopes."""
        clean_name = package_name.lower().strip()
        for allowed in self.allowed_packages:
            norm_allowed = allowed.lower().strip()
            if norm_allowed == clean_name or fnmatch.fnmatch(clean_name, norm_allowed):
                return True
        return False

    def is_detector_enabled(self, detector_name: str) -> bool:
        """Check if detector is enabled."""
        return detector_name.lower() not in [d.lower() for d in self.disabled_detectors]


def load_config(root_path: Path) -> SoberConfig:
    """Load configuration from sober.toml, .sober.toml, or pyproject.toml."""
    candidates = [
        root_path / "sober.toml",
        root_path / ".sober.toml",
        root_path / "pyproject.toml",
    ]

    for candidate in candidates:
        if candidate.is_file():
            try:
                content = candidate.read_bytes()
                data = tomllib.loads(content.decode("utf-8", errors="replace"))

                section: dict[str, Any] = {}
                if candidate.name == "pyproject.toml":
                    section = data.get("tool", {}).get("sober", {})
                else:
                    section = data.get("sober", data)

                if not section and candidate.name == "pyproject.toml":
                    continue

                return SoberConfig(
                    min_score=float(section.get("min_score", 95.0)),
                    fail_on_critical=bool(section.get("fail_on_critical", True)),
                    ignore_paths=list(section.get("ignore_paths", [])),
                    allowed_packages=list(section.get("allowed_packages", [])),
                    disabled_detectors=list(section.get("disabled_detectors", [])),
                    custom_secret_patterns=list(section.get("custom_secret_patterns", [])),
                    max_workers=int(section.get("max_workers", 10)),
                )
            except Exception:
                # If TOML has errors, skip to next candidate
                continue

    return SoberConfig()
