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
    """Validate a URL as text only; never make a network request."""
    value = raw.strip()
    if not value:
        raise ValueError("Enter a URL first.")
    if len(value) > 2048:
        raise ValueError("The URL is too long (maximum 2,048 characters).")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError("The URL contains invalid control characters.")
    if any(ch.isspace() for ch in value):
        raise ValueError("The URL contains spaces. Check the address and try again.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "https://" + value
    try:
        parsed = urlparse(value)
        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("Only http:// and https:// URLs can be checked.")
        if not parsed.hostname:
            raise ValueError("Enter a complete domain name, such as example.com.")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("URLs containing embedded usernames or passwords are not accepted.")
        host = parsed.hostname.rstrip(".")
        if not host or "." not in host:
            raise ValueError("Enter a complete domain name, such as example.com.")
        # Accessing .port validates malformed and out-of-range ports.
        port = parsed.port
        if port is not None and not (1 <= port <= 65535):
            raise ValueError("The URL contains an invalid port.")
        # Reject malformed host labels while allowing valid internationalized domains.
        ascii_host = host.encode("idna").decode("ascii")
        if len(ascii_host) > 253:
            raise ValueError("The hostname is too long.")
        labels = ascii_host.split(".")
        if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
               or not re.fullmatch(r"[A-Za-z0-9-]+", label) for label in labels):
            raise ValueError("The hostname format is invalid.")
    except (UnicodeError, ValueError) as exc:
        if isinstance(exc, ValueError) and str(exc).startswith(("Enter ", "Only ", "URLs ", "The URL", "The hostname")):
            raise
        raise ValueError("The URL format is invalid. Check the hostname and port.") from exc
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
