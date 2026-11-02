from sober.core.manifest import ManifestInspector


def test_manifest_inspector_pyproject(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("""
[project]
dependencies = [
    "requests>=2.28.0",
    "rich==13.7.0",
    "flask[async]",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0.0",
    "ruff"
]
""")

    inspector = ManifestInspector(tmp_path)
    assert inspector.is_declared_python_package("requests") is True
    assert inspector.is_declared_python_package("rich") is True
    assert inspector.is_declared_python_package("flask") is True
    assert inspector.is_declared_python_package("pytest") is True
    assert inspector.is_declared_python_package("ruff") is True
    assert inspector.is_declared_python_package("django") is False


def test_manifest_inspector_requirements(tmp_path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("""
# Core dependencies
fastapi>=0.100.0
uvicorn[standard]
pydantic-settings
""")

    inspector = ManifestInspector(tmp_path)
    assert inspector.is_declared_python_package("fastapi") is True
    assert inspector.is_declared_python_package("uvicorn") is True
    assert inspector.is_declared_python_package("pydantic-settings") is True
    assert inspector.is_declared_python_package("pydantic_settings") is True


def test_manifest_inspector_package_json(tmp_path):
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text("""{
  "name": "my-app",
  "dependencies": {
    "react": "^18.2.0",
    "@tanstack/react-query": "^5.0.0"
  },
  "devDependencies": {
    "typescript": "^5.0.0"
  }
}""")

    inspector = ManifestInspector(tmp_path)
    assert inspector.is_declared_js_package("react") is True
    assert inspector.is_declared_js_package("@tanstack/react-query") is True
    assert inspector.is_declared_js_package("typescript") is True
    assert inspector.is_declared_js_package("vue") is False
