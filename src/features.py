"""Shared URL normalization and feature extraction for PhishGuard AI."""
from __future__ import annotations
import ipaddress
import re
from urllib.parse import urlparse

FEATURE_NAMES = [
    "url_length", "hostname_length", "dot_count", "hyphen_count",
    "digit_count", "at_count", "question_count", "dash_count",
    "uses_https", "has_ip_host", "subdomain_count", "has_suspicious_word",
    "has_url_shortener", "path_length", "query_length",
]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly"}
SUSPICIOUS = {"login", "verify", "account", "update", "secure", "password", "banking", "signin", "confirm", "wallet", "recover"}

def normalize_url(raw: str) -> str:
    value = raw.strip()
    if not value:
        raise ValueError("Enter a URL first.")
    if any(ord(ch) < 32 for ch in value):
        raise ValueError("URL contains invalid control characters.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only http and https URLs are supported.")
    if not parsed.hostname or "." not in parsed.hostname:
        raise ValueError("Enter a complete domain, such as example.com.")
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("URL contains an invalid port.") from exc
    return value

def extract_features(raw: str) -> dict[str, int]:
    url = normalize_url(raw)
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower().rstrip(".")
    labels = [part for part in host.split(".") if part]
    try:
        ipaddress.ip_address(host.strip("[]"))
        is_ip = 1
    except ValueError:
        is_ip = 0
    lowered = url.lower()
    return {
        "url_length": len(url),
        "hostname_length": len(host),
        "dot_count": url.count("."),
        "hyphen_count": url.count("-"),
        "digit_count": sum(c.isdigit() for c in url),
        "at_count": url.count("@"),
        "question_count": url.count("?"),
        "dash_count": url.count("-"),
        "uses_https": int(parsed.scheme.lower() == "https"),
        "has_ip_host": is_ip,
        "subdomain_count": max(0, len(labels) - 2),
        "has_suspicious_word": int(any(word in lowered for word in SUSPICIOUS)),
        "has_url_shortener": int(host in SHORTENERS),
        "path_length": len(parsed.path),
        "query_length": len(parsed.query),
    }
