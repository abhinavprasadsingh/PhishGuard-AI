import pytest
from src.features import FEATURE_NAMES, extract_features, normalize_url

def test_adds_scheme_to_domain():
    assert normalize_url("example.com").startswith("https://")

def test_rejects_empty_input():
    with pytest.raises(ValueError):
        normalize_url("  ")

def test_rejects_non_http_scheme():
    with pytest.raises(ValueError):
        normalize_url("javascript:alert(1)")

def test_https_and_host_features():
    features = extract_features("https://login.example.com/account")
    assert features["uses_https"] == 1
    assert features["hostname_length"] > 0
    assert features["has_suspicious_word"] == 1
    assert len(features) == len(FEATURE_NAMES)

def test_shortener_detection():
    assert extract_features("https://bit.ly/abc")["has_url_shortener"] == 1

def test_ip_host_detection():
    assert extract_features("http://192.0.2.1/login")["has_ip_host"] == 1

def test_invalid_port():
    with pytest.raises(ValueError):
        normalize_url("https://example.com:99999")
