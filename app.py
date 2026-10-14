from __future__ import annotations

import ipaddress
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
    if any(ch.isspace() for ch in value):
        raise ValueError("The URL contains spaces. Check the address and try again.")
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


def heuristic_assessment(features: dict[str, int]) -> tuple[str, int, list[str]]:
    reasons = []
    if features["has_ip_host"]:
        reasons.append("The hostname is an IP address rather than a typical domain.")
    if features["has_url_shortener"]:
        reasons.append("The hostname belongs to a known URL-shortening service, which can hide the final destination.")
    if features["has_suspicious_word"]:
        reasons.append("The URL contains a word often used in account or security lures.")
    if features["at_count"]:
        reasons.append("The URL contains an @ symbol, which can make the destination confusing.")
    if features["subdomain_count"] >= 3:
        reasons.append("The hostname has several subdomain levels. Check which domain actually owns the site.")
    if features["url_length"] >= 100:
        reasons.append("The URL is unusually long.")
    if features["hyphen_count"] >= 3:
        reasons.append("The URL contains multiple hyphens.")
    if not features["uses_https"]:
        reasons.append("The URL does not use HTTPS.")
    score = min(95, len(reasons) * 15)
    label = "Higher-risk signals" if score >= 45 else "Some caution advised" if score >= 15 else "Fewer obvious signals"
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


st.set_page_config(page_title="PhishGuard AI | URL Risk Lab", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@400;500;600;700&display=swap');
:root { color-scheme: dark; }
html, body, [class*="css"] { font-family: 'DM Sans', sans-serif; }
.stApp {
  background:
    radial-gradient(ellipse at 8% 0%, rgba(25, 91, 115, .28), transparent 34%),
    radial-gradient(ellipse at 95% 20%, rgba(31, 77, 124, .18), transparent 30%),
    #070c14;
  color: #e9f1fb;
}
.block-container { max-width: 1220px; padding-top: 1.15rem; padding-bottom: 3.5rem; }
[data-testid="stHeader"] { background: rgba(7,12,20,.78); }
[data-testid="stSidebar"] { background: linear-gradient(180deg,#0d1827 0%,#0a111c 100%); border-right: 1px solid #1d3043; }
[data-testid="stSidebar"] > div { padding-top: 1.4rem; }
.hero {
  position: relative; overflow: hidden; padding: clamp(1.5rem,4vw,3.1rem);
  border: 1px solid rgba(83, 224, 204, .24); border-radius: 28px;
  background: linear-gradient(120deg,rgba(18,47,67,.98),rgba(11,21,37,.98) 62%,rgba(12,29,48,.96));
  margin: .3rem 0 1.8rem; box-shadow: 0 22px 65px rgba(0,0,0,.22);
}
.hero:after { content:""; position:absolute; width:260px; height:260px; right:-85px; top:-105px; border:1px solid rgba(105,230,207,.13); border-radius:50%; box-shadow:0 0 0 30px rgba(105,230,207,.025),0 0 0 65px rgba(105,230,207,.02); pointer-events:none; }
.eyebrow { color:#72ead6; letter-spacing:.19em; text-transform:uppercase; font-size:.72rem; font-weight:800; }
.hero h1 { font-family:'Space Grotesk',sans-serif; font-size:clamp(2.4rem,5.5vw,4.2rem); line-height:1.03; letter-spacing:-.045em; margin:.8rem 0 .9rem; color:#f3f7ff; }
.hero p { color:#bdcddd; font-size:1.05rem; line-height:1.75; max-width:760px; }
.pill { display:inline-flex; align-items:center; padding:.42rem .75rem; border:1px solid #31566b; border-radius:999px; color:#d0e3ed; font-size:.76rem; margin:.4rem .35rem 0 0; background:rgba(8,20,33,.35); }
.panel { padding:1.25rem 1.3rem; border-radius:18px; background:linear-gradient(145deg,rgba(17,33,52,.94),rgba(12,23,37,.92)); border:1px solid #23394e; height:100%; box-shadow:0 10px 28px rgba(0,0,0,.10); }
.muted, [data-testid="stCaptionContainer"] { color:#9aafc5; font-size:.9rem; }
h1,h2,h3,h4 { font-family:'Space Grotesk',sans-serif !important; letter-spacing:-.025em; }
h2, h3 { color:#f0f6ff; }
p { line-height:1.65; }
div[data-testid="stMetric"] { background:linear-gradient(145deg,rgba(19,39,60,.95),rgba(12,25,41,.95)); border:1px solid #2b475e; padding:1rem 1.1rem; border-radius:16px; }
div[data-testid="stMetricLabel"] { color:#a8bfd2; }
div[data-testid="stMetricValue"] { color:#75ead6; font-family:'Space Grotesk',sans-serif; }
.stTextInput input { background:#0c1726 !important; border:1px solid #2c435a !important; border-radius:12px !important; min-height:3.15rem; color:#f2f7ff !important; }
.stTextInput input:focus { border-color:#69e6cf !important; box-shadow:0 0 0 1px #69e6cf !important; }
.stButton button, .stFormSubmitButton button { border-radius:12px; font-weight:700; min-height:2.9rem; transition:all .18s ease; }
.stButton button[kind="primary"], .stFormSubmitButton button[kind="primary"] { background:linear-gradient(100deg,#58ddc8,#8af0d9); color:#07151d; border:0; }
.stButton button[kind="primary"]:hover, .stFormSubmitButton button[kind="primary"]:hover { filter:brightness(1.06); box-shadow:0 7px 24px rgba(87,221,200,.18); }
div[data-testid="stExpander"] { border:1px solid #22394e; border-radius:14px; background:rgba(11,22,36,.55); overflow:hidden; }
div[data-testid="stDataFrame"] { border:1px solid #20364d; border-radius:12px; overflow:hidden; }
hr { border-color:#213449; }
a { color:#77e9d7 !important; }
footer {visibility:hidden;}
@media (max-width: 700px) {
  .block-container { padding: .7rem .85rem 2.5rem; }
  .hero { border-radius:20px; padding:1.4rem; }
  .hero p { font-size:.98rem; }
  .pill { font-size:.7rem; }
}
</style>
<div class="hero">
  <div class="eyebrow">Threat awareness · URL intelligence</div>
  <h1>PhishGuard <span style="color:#69e6cf">AI</span></h1>
  <p>Pause before you click. Understand the signals behind a suspicious link with a transparent, privacy-minded URL risk assessment.</p>
  <span class="pill">⌕ Explainable signals</span><span class="pill">⌁ No URL visits</span><span class="pill">✳ ML-ready</span>
</div>
""", unsafe_allow_html=True)

with st.sidebar:
    st.markdown("## 🛡️ PhishGuard")
    st.caption("YOUR POCKET URL RISK LAB")
    st.markdown("---")
    st.markdown("**What this tool checks**")
    st.write("URL structure, hostname patterns, suspicious words, shortening services, and other simple signals.")
    st.markdown("---")
    st.markdown("**Privacy by design**")
    st.write("The submitted URL is parsed as text. This app does not visit it, follow redirects, or fetch webpage content.")
    st.markdown("---")
    st.caption("A low score is not a safety guarantee.")
    st.markdown("---")
    st.markdown("**Project resources**")
    st.markdown("[GitHub repository](https://github.com/abhinavprasadsingh/PhishGuard-AI)")
    st.markdown("[Evaluation methodology](https://github.com/abhinavprasadsingh/PhishGuard-AI/blob/main/reports/evaluation.md)")
    st.markdown("[Viva / technical notes](https://github.com/abhinavprasadsingh/PhishGuard-AI/blob/main/docs/VIVA.md)")

st.markdown("### 🔍 Inspect a link")
st.write("Paste a URL to inspect its structure. Do not include private tokens, session IDs, or personal information.")
with st.form("url_analysis_form", clear_on_submit=False):
    url_input = st.text_input("URL to inspect", placeholder="https://example.com/account", help="You can include or omit https://")
    submitted = st.form_submit_button("Analyze URL  →", type="primary", use_container_width=True)

if submitted:
    try:
        normalized = normalize_url(url_input)
        features = extract_features(normalized)
        model = load_model()
        st.markdown("---")
        st.markdown("### Assessment")
        if model is not None:
            try:
                import pandas as pd
                row = pd.DataFrame([[features[name] for name in FEATURES]], columns=FEATURES)
                pred = int(model.predict(row)[0])
                probabilities = model.predict_proba(row)[0] if hasattr(model, "predict_proba") else None
                # For binary classifiers, confidence is the predicted-class probability, not a safety score.
                confidence = float(max(probabilities)) if probabilities is not None else None
                label = "Potential phishing" if pred == 1 else "Model classifies as likely legitimate"
                left, right = st.columns([2, 1])
                with left:
                    st.subheader(label)
                    st.write("This result comes from the locally saved supervised model. Review the limitations and verify the domain independently.")
                with right:
                    if confidence is not None:
                        st.metric("Model confidence", f"{confidence:.0%}")
                    else:
                        st.metric("Model output", str(pred))
                st.info("Model confidence is not the probability that a URL is safe. A model can be wrong, especially on unfamiliar URLs.")
            except Exception as exc:
                st.warning("The saved model could not be used with the expected feature schema. Showing heuristic demo mode instead.")
                label, score, reasons = heuristic_assessment(features)
                model = None
        if model is None:
            label, score, reasons = heuristic_assessment(features)
            left, right = st.columns([2, 1])
            with left:
                st.subheader(label)
                st.write("**Heuristic demo mode** — these are simple URL-pattern checks, not a trained ML prediction.")
                st.markdown("**Signals to review**")
                for reason in reasons:
                    st.markdown(f"- {reason}")
            with right:
                st.metric("Heuristic signal score", f"{score}/100", help="A rule-based indicator only; not a calibrated probability.")
                st.progress(score / 100)
                st.caption("Higher means more listed patterns matched, not a measured probability of fraud.")
        # Keep transparent rule-based indicators separate from any trained-model output.
        _, rule_score, rule_reasons = heuristic_assessment(features)
        with st.expander("🧭 URL warning signals to review", expanded=True):
            if rule_reasons and rule_reasons != ["No simple warning patterns were detected. This does not prove the site is safe."]:
                for reason in rule_reasons:
                    st.markdown(f"- {reason}")
            else:
                st.write("No simple warning patterns were detected. This does not prove the URL is safe.")
            st.caption(f"Rule-based indicator score: {rule_score}/100. This is not a probability and is not the trained model's explanation.")
        with st.expander("🧬 Explore extracted URL features"):
            rows = [{"Feature": key.replace("_", " ").title(), "Value": str(value)} for key, value in features.items()]
            st.dataframe(rows, hide_index=True, use_container_width=True)
        with st.expander("🧭 Safe next steps"):
            st.markdown("- Check the registered domain carefully, not just the brand name in the URL.")
            st.markdown("- Reach important services through a bookmark or by typing their known address yourself.")
            st.markdown("- Never enter passwords or one-time codes after following an unexpected message link.")
            st.markdown("- If in doubt, ask the organization through a separate, trusted channel.")
        with st.expander("ℹ️ Methodology, limitations & project links"):
            st.write("The app parses the URL string locally. It does not request the destination, follow redirects, inspect page content, or verify domain reputation. URL patterns can produce false positives and false negatives.")
            st.markdown("- [GitHub source code](https://github.com/abhinavprasadsingh/PhishGuard-AI)")
            st.markdown("- [Model evaluation methodology](https://github.com/abhinavprasadsingh/PhishGuard-AI/blob/main/reports/evaluation.md)")
            st.markdown("- [Technical notes / viva preparation](https://github.com/abhinavprasadsingh/PhishGuard-AI/blob/main/docs/VIVA.md)")
            st.caption("Evaluation metrics are only available after training and testing on a documented labeled dataset. No metrics are claimed by this demo.")
    except ValueError as exc:
        st.error(str(exc))
else:
    st.markdown("""
    <div class="panel">
      <h4>Ready when you are</h4>
      <p class="muted">Enter a URL above and select Analyze URL to see a structured assessment. No URL is checked until you submit the form.</p>
    </div>
    """, unsafe_allow_html=True)
    st.markdown("#### What you'll get")
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown('<div class="panel"><h4>🔎 Clear signals</h4><p class="muted">Understand which URL patterns triggered caution, without a black-box verdict.</p></div>', unsafe_allow_html=True)
    with c2:
        st.markdown('<div class="panel"><h4>🧬 Feature breakdown</h4><p class="muted">Explore hostname, length, protocol, and other structural indicators.</p></div>', unsafe_allow_html=True)
    with c3:
        st.markdown('<div class="panel"><h4>🔐 Privacy-minded</h4><p class="muted">The app analyzes text only and never opens the destination URL.</p></div>', unsafe_allow_html=True)

st.markdown("---")
st.markdown('<p class="muted">PhishGuard AI is an educational awareness project, not a guarantee of safety or a replacement for browser protection and professional security tools.</p>', unsafe_allow_html=True)
