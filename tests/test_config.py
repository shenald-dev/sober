from sober.core.config import SoberConfig, load_config


def test_default_config():
    config = SoberConfig()
    assert config.min_score == 95.0
    assert config.fail_on_critical is True
    assert config.max_workers == 10
    assert config.is_detector_enabled("hallucinations") is True
    assert config.is_path_ignored("src/main.py") is False
    assert config.is_package_whitelisted("some-pkg") is False


def test_load_config_sober_toml(tmp_path):
    toml_file = tmp_path / "sober.toml"
    toml_file.write_text("""
[sober]
min_score = 90.0
fail_on_critical = false
ignore_paths = ["tests/*", "migrations/*.py"]
allowed_packages = ["@myorg/*", "internal-lib"]
disabled_detectors = ["duplicates"]
max_workers = 4
""")

    config = load_config(tmp_path)
    assert config.min_score == 90.0
    assert config.fail_on_critical is False
    assert config.max_workers == 4
    assert config.is_detector_enabled("duplicates") is False
    assert config.is_detector_enabled("security") is True

    # Path ignoring tests
    assert config.is_path_ignored("tests/test_foo.py") is True
    assert config.is_path_ignored("migrations/0001_init.py") is True
    assert config.is_path_ignored("src/app.py") is False

    # Package whitelist tests
    assert config.is_package_whitelisted("@myorg/core") is True
    assert config.is_package_whitelisted("@myorg/ui") is True
    assert config.is_package_whitelisted("internal-lib") is True
    assert config.is_package_whitelisted("external-pkg") is False


def test_load_config_pyproject_toml(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("""
[tool.sober]
min_score = 85.0
allowed_packages = ["company-*"]
""")

    config = load_config(tmp_path)
    assert config.min_score == 85.0
    assert config.is_package_whitelisted("company-auth") is True
    assert config.is_package_whitelisted("other-auth") is False


def test_load_config_fallback_on_corrupted_file(tmp_path):
    bad_toml = tmp_path / "sober.toml"
    bad_toml.write_text("invalid [ [ toml syntax")

    config = load_config(tmp_path)
    assert config.min_score == 95.0
