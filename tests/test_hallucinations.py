from sober.core.scanner import FileToAudit
from sober.detectors import Severity
from sober.detectors.hallucinations import (
    _REGISTRY_CACHE,
    audit_hallucinations,
    extract_js_imports,
    extract_python_imports,
)


def test_python_stdlib_not_flagged(tmp_path):
    f = tmp_path / "valid.py"
    f.write_text("import sys\nimport os\nimport json\nfrom datetime import datetime\n")
    issues = audit_hallucinations(FileToAudit(f), tmp_path)
    assert len(issues) == 0


def test_node_builtins_not_flagged(tmp_path):
    f = tmp_path / "valid.ts"
    f.write_text("import fs from 'fs';\nimport path from 'path';\n")
    issues = audit_hallucinations(FileToAudit(f), tmp_path)
    assert len(issues) == 0


def test_hallucinated_pypi_package_flagged(tmp_path):
    # Mock registry cache to simulate confirmed 404 for nonexistent package
    _REGISTRY_CACHE["totally-fake-hallucinated-package-xyz123"] = False
    f = tmp_path / "ai_code.py"
    f.write_text("import totally_fake_hallucinated_package_xyz123\n")

    issues = audit_hallucinations(FileToAudit(f), tmp_path)
    assert len(issues) == 1
    assert issues[0].severity == Severity.CRITICAL
    assert "totally_fake_hallucinated_package_xyz123" in issues[0].title


def test_extract_python_imports_edge_cases():
    code = """
import numpy as np
from foo.bar import baz
from typing import List, Dict

def test():
    import local_mod
"""
    imports = extract_python_imports(code)
    pkgs = [p[0] for p in imports]
    assert "numpy" in pkgs
    assert "foo" in pkgs
    assert "typing" in pkgs
    assert "local_mod" in pkgs

    # Test fallback syntax error
    bad_code = """
import requests
from django import db
def func(
"""
    imports = extract_python_imports(bad_code)
    pkgs = [p[0] for p in imports]
    assert "requests" in pkgs
    assert "django" in pkgs


def test_extract_js_imports_edge_cases():
    code = """
import { useState } from 'react';
import * as _ from "lodash";
import myDefault from '@scope/package';
import '@emotion/core';
const express = require('express');
const { a, b } = require('@scope/pkg2/path');
import relative from './local/path';
import absolute from '/root/path';
"""
    imports = extract_js_imports(code)
    pkgs = [p[0] for p in imports]
    assert "react" in pkgs
    assert "lodash" in pkgs
    assert "@scope/package" in pkgs
    assert "@emotion/core" in pkgs
    assert "express" in pkgs
    assert "@scope/pkg2" in pkgs
    assert "./local/path" not in pkgs
    assert "/root/path" not in pkgs
