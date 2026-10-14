from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

import streamlit as st

ROOT = Path(__file__).resolve().parent
MODEL_PATH = ROOT / "models" / "phishing_model.joblib"
FEATURES = [
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
        raise ValueError("The URL contains invalid control characters.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only http:// and https:// URLs can be checked.")
    if not parsed.hostname or "." not in parsed.hostname:
        raise ValueError("Enter a complete domain name, such as example.com.")
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("The URL contains an invalid port.") from exc
    return value


def extract_features(raw: str) -> dict[str, int]:
    url = normalize_url(raw)
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower().rstrip(".")
    labels = [part for part in host.split(".") if part]
    lowered = url.lower()
    try:
        import ipaddress
        is_ip = int(ipaddress.ip_address(host.strip("[]")) is not None)
    except ValueError:
        is_ip = 0
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


def heuristic_assessment(features: dict[str, int]) -> tuple[str, int, list[str]]:
    reasons = []
    if features["has_ip_host"]:
        reasons.append("The hostname is an IP address rather than a typical domain.")
    if features["has_url_shortener"]:
        reasons.append("The hostname belongs to a known URL-shortening service.")
    if features["has_suspicious_word"]:
        reasons.append("The URL contains a word often used in account or security lures.")
    if features["at_count"]:
        reasons.append("The URL contains an @ symbol, which can obscure the destination.")
    if features["subdomain_count"] >= 3:
        reasons.append("The hostname has several subdomain levels.")
    if features["url_length"] >= 100:
        reasons.append("The URL is unusually long.")
    if features["hyphen_count"] >= 3:
        reasons.append("The URL contains multiple hyphens.")
    if not features["uses_https"]:
        reasons.append("The URL does not use HTTPS.")
    score = min(95, len(reasons) * 15)
    if score >= 45:
        label = "Higher-risk signals"
    elif score >= 15:
        label = "Some caution advised"
    else:
        label = "Fewer obvious signals"
    if not reasons:
        reasons.append("No simple warning patterns were detected. This does not prove the site is safe.")
    return label, score, reasons


def load_model():
    if not MODEL_PATH.exists():
        return None
    try:
        import joblib
        return joblib.load(MODEL_PATH)
    except Exception:
        return None


st.set_page_config(page_title="PhishGuard AI", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
st.markdown("""
<style>
:root { color-scheme: dark; }
.stApp { background: radial-gradient(ellipse at 12% 0%, #122b45 0, #080f1c 45%, #070b13 100%); color: #e8eef8; }
.block-container { max-width: 1180px; padding-top: 2rem; padding-bottom: 3rem; }
.hero { padding: 1.8rem 2rem; border: 1px solid #24435c; border-radius: 22px; background: linear-gradient(120deg, rgba(19,49,73,.92), rgba(12,21,37,.96)); margin-bottom: 1.2rem; }
.eyebrow { color: #69e6cf; letter-spacing: .18em; text-transform: uppercase; font-size: .75rem; font-weight: 800; }
.hero h1 { font-size: clamp(2rem, 5vw, 3.3rem); line-height: 1.1; margin: .55rem 0; color: #f3f7ff; }
.hero p { color: #b6c6da; font-size: 1.05rem; max-width: 760px; }
.panel { padding: 1.2rem; border-radius: 16px; background: rgba(16,29,47,.8); border: 1px solid #20364d; }
.small-muted { color: #91a5bd; font-size: .9rem; }
div[data-testid="stMetric"] { background: rgba(17,34,54,.78); border: 1px solid #24415a; padding: 1rem; border-radius: 14px; }
.stButton button[kind="primary"] { border-radius: 10px; font-weight: 700; }
</style>
<div class="hero">
  <div class="eyebrow">Threat awareness • URL analysis</div>
  <h1>PhishGuard <span style="color:#69e6cf">AI</span></h1>
  <p>Inspect URL patterns before you click. Get a clear, explainable risk assessment designed for learning and awareness.</p>
</div>
""", unsafe_allow_html=True)

with st.sidebar:
    st.markdown("## 🛡️ PhishGuard")
    st.caption("Educational security lab")
    st.markdown("---")
    st.markdown("**What this tool does**")
    st.write("Checks URL structure and explains suspicious signals. It never opens or visits the URL you submit.")
    st.markdown("---")
    st.caption("A low warning score is not a safety guarantee.")

st.markdown("### Analyze a URL")
st.write("Paste a link below. For your safety, do not enter private tokens or personal information in URLs.")
url_input = st.text_input("URL to inspect", placeholder="https://example.com/account", label_visibility="collapsed")
analyze = st.button("Analyze URL  →", type="primary", use_container_width=True)

if analyze:
    try:
        normalized = normalize_url(url_input)
        features = extract_features(normalized)
        model = load_model()
        st.markdown("---")
        if model is not None:
            try:
                import pandas as pd
                import numpy as np
                row = pd.DataFrame([[features[name] for name in FEATURES]], columns=FEATURES)
                pred = int(model.predict(row)[0])
                probabilities = model.predict_proba(row)[0] if hasattr(model, "predict_proba") else None
                score = int(float(max(probabilities)) * 100) if probabilities is not None else None
                label = "Potential phishing" if pred == 1 else "Likely legitimate"
                st.subheader("Model assessment")
                st.metric("Prediction", label)
                if score is not None:
                    st.metric("Model confidence", f"{score}%")
                st.info("Prediction comes from the locally saved supervised model. Model confidence is not a guarantee.")
            except Exception:
                label, score, reasons = heuristic_assessment(features)
                st.warning("The saved model could not be used with this feature schema. Showing transparent heuristic mode instead.")
                st.subheader(label)
                st.progress(score / 100)
                for reason in reasons:
                    st.write("• " + reason)
        else:
            label, score, reasons = heuristic_assessment(features)
            left, right = st.columns([2, 1])
            with left:
                st.subheader(label)
                st.write("This is **heuristic demo mode**, not a trained ML prediction. Add a trained model to enable supervised classification.")
                for reason in reasons:
                    st.write("• " + reason)
            with right:
                st.metric("Heuristic signal score", f"{score}/100")
                st.progress(score / 100)
        st.markdown("#### Extracted URL features")
        st.dataframe([{"Feature": key.replace("_", " ").title(), "Value": value} for key, value in features.items()], hide_index=True, use_container_width=True)
        with st.expander("URL handling & limitations"):
            st.write("The app parses the text locally and does not request the submitted URL, follow redirects, or download page content.")
            st.write("URL patterns can be misleading in both directions. Always verify the domain independently and never enter credentials after following an unexpected link.")
    except ValueError as exc:
        st.error(str(exc))

st.markdown("---")
c1, c2, c3 = st.columns(3)
with c1:
    st.markdown("#### 🔎 Explainable")
    st.caption("Shows which URL patterns triggered warnings.")
with c2:
    st.markdown("#### 🧪 ML-ready")
    st.caption("Supports a locally trained scikit-learn model when available.")
with c3:
    st.markdown("#### 🔐 Privacy-minded")
    st.caption("Does not visit submitted URLs.")
st.caption("PhishGuard AI is an educational project, not a replacement for browser protection, security tools, or expert review.")
