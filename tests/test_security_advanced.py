from sober.core.scanner import FileToAudit
from sober.detectors import Severity
from sober.detectors.security import audit_security


def test_detects_expanded_ai_and_cloud_keys(tmp_path):
    gemini_key = "AIza" + "SyD-1234567890abcdef1234567890abcdef"
    hf_token = "hf_" + "abcdefghijklmnopqrstuvwxyz12345678"
    stripe_key = "sk_" + "live_" + "1234567890abcdef12345678"
    pinecone_key = "pcsk_" + "1234567890abcdef1234567890abcdef1234567890abcdef"

    f = tmp_path / "secrets.ts"
    f.write_text(f"""
const GEMINI_KEY = "{gemini_key}";
const HF_TOKEN = "{hf_token}";
const STRIPE_SECRET = "{stripe_key}";
const PINECONE_KEY = "{pinecone_key}";
""")

    issues = audit_security(FileToAudit(f), tmp_path)
    assert len(issues) == 4
    assert all(i.severity == Severity.CRITICAL for i in issues)
    assert any("Gemini" in i.title for i in issues)
    assert any("Hugging Face" in i.title for i in issues)
    assert any("Stripe" in i.title for i in issues)
    assert any("Pinecone" in i.title for i in issues)


def test_detects_insecure_tls_and_unsafe_deserialization(tmp_path):
    f = tmp_path / "insecure.py"
    f.write_text("""import requests
import pickle
import yaml

def fetch(url, data):
    resp = requests.get(url, verify=False)
    obj = pickle.loads(data)
    cfg = yaml.load(data, Loader=yaml.UnsafeLoader)
    return obj
""")

    issues = audit_security(FileToAudit(f), tmp_path)
    assert len(issues) == 3
    assert any("TLS/SSL" in i.title for i in issues)
    assert any("pickle" in i.title for i in issues)
    assert any("YAML" in i.title for i in issues)


def test_custom_secret_patterns(tmp_path):
    f = tmp_path / "internal.py"
    f.write_text("""
INTERNAL_SECRET = "corp_secret_abcdef1234567890abcdef12"
""")

    custom_rules = [{"name": "Corporate Token", "pattern": r"corp_secret_[a-z0-9]{24}"}]
    issues = audit_security(FileToAudit(f), tmp_path, custom_secret_patterns=custom_rules)
    assert len(issues) == 1
    assert issues[0].title == "Corporate Token"
