import json
from pathlib import Path
from datetime import datetime

import streamlit as st

from core.analyzer import analyze_email
from core.report import build_report_filename, generate_json_report


def load_css(file_name: str) -> None:
    css_path = Path(file_name)
    if css_path.exists():
        with open(css_path, "r", encoding="utf-8") as css_file:
            st.markdown(f"<style>{css_file.read()}</style>", unsafe_allow_html=True)


def verdict_class(score: int) -> str:
    if score < 25:
        return "risk-low"
    if score < 50:
        return "risk-mid"
    return "risk-high"


def load_sample_emails() -> list[dict]:
    sample_path = Path("data/sample_emails.json")
    if not sample_path.exists():
        return []

    with open(sample_path, "r", encoding="utf-8") as sample_file:
        return json.load(sample_file)


def render_flag_items(flags: list[str]) -> str:
    if not flags:
        return '<div class="status-empty">No red flags triggered by the current rule set.</div>'

    html = ""
    for flag in flags:
        html += f'<div class="flag-item"><span class="item-icon">!</span><span>{flag}</span></div>'
    return html


def render_url_items(urls: list[str]) -> str:
    if not urls:
        return '<div class="status-empty">No URLs found in the submitted email body.</div>'

    html = ""
    for url in urls:
        html += f'<div class="url-item"><span class="item-icon">LINK</span><span>{url}</span></div>'
    return html


def render_indicator_items(flags: list[str], url_score: int, has_result: bool) -> str:
    flag_text = " ".join(flag.lower() for flag in flags)
    indicators = [
        ("Urgent Language", "urgent language" in flag_text, "ALRT"),
        (
            "Credential Requests",
            "credential" in flag_text or "verification request" in flag_text,
            "ALRT",
        ),
        (
            "Suspicious Domains",
            "suspicious sender" in flag_text or "domain pattern" in flag_text,
            "ALRT",
        ),
        ("Risky URLs", url_score > 0, "ALRT"),
    ]

    html = ""
    for label, is_active, active_text in indicators:
        status_class = "indicator-active" if is_active else "indicator-idle"
        status_text = active_text if is_active else ("CHK" if has_result else "SCAN")
        html += (
            f'<div class="indicator-item {status_class}">'
            f'<span class="item-icon">{status_text}</span><span>{label}</span></div>'
        )
    return html


def shield_state(score: int, verdict: str) -> tuple[str, str]:
    if score >= 50:
        return "shield-danger", "RISK"
    if score >= 25:
        return "shield-warn", "WARN"
    if verdict == "Awaiting Analysis":
        return "shield-idle", "SCAN"
    return "shield-safe", "OK"


def build_analyst_explanation(result: dict | None) -> str:
    if not result:
        return (
            "Submit or load an email sample to generate an analyst-style explanation of the "
            "verdict, key signals, and recommended handling steps."
        )

    verdict = result["verdict"]
    flags = result.get("flags", [])
    details = result.get("details", [])
    urls_found = result.get("urls_found", [])
    url_score = result.get("url_score", 0)

    if not flags:
        return (
            "No strong phishing indicators were triggered by the current rule set. The message "
            "still deserves normal verification hygiene, but the analyzer did not find high-signal "
            "social engineering or link-based risk patterns."
        )

    lead_detail = details[0] if details else "The result is driven by rule-based phishing indicators."
    url_context = (
        f" URL analysis added {url_score} risk points across {len(urls_found)} extracted link(s)."
        if url_score > 0
        else ""
    )
    return (
        f"This email was classified as {verdict.lower()} after PhishNyx identified "
        f"{len(flags)} phishing indicator(s). {lead_detail}{url_context}"
    )


def build_recent_scan_item(sender: str, subject: str, result: dict) -> dict:
    return {
        "sender": sender.strip() or "Not provided",
        "subject": subject.strip() or "No subject",
        "verdict": result["verdict"],
        "score": result["score"],
        "timestamp": datetime.now().strftime("%H:%M"),
    }


def render_recent_scans(history: list[dict]) -> str:
    if not history:
        return '<div class="status-empty">Recent analyses will appear here after you scan an email.</div>'

    html = ""
    for item in history:
        html += (
            '<div class="history-item">'
            f'<div class="history-top"><span class="history-verdict">{item["verdict"]}</span>'
            f'<span class="history-score">{item["score"]}/100</span></div>'
            f'<div class="history-subject">{item["subject"]}</div>'
            f'<div class="history-meta">{item["sender"]} &bull; {item["timestamp"]}</div>'
            '</div>'
        )
    return html


st.set_page_config(
    page_title="PhishNyx AI",
    page_icon="P",
    layout="wide",
    initial_sidebar_state="collapsed",
)

load_css("styles.css")
sample_emails = load_sample_emails()

if "sender_input" not in st.session_state:
    st.session_state.sender_input = ""
if "subject_input" not in st.session_state:
    st.session_state.subject_input = ""
if "body_input" not in st.session_state:
    st.session_state.body_input = ""
if "recent_scans" not in st.session_state:
    st.session_state.recent_scans = []

st.markdown(
    """
    <div class="scene-backdrop">
        <div class="aurora aurora-a"></div>
        <div class="aurora aurora-b"></div>
        <div class="aurora aurora-c"></div>
        <div class="particle-field particle-stars"></div>
        <div class="particle-field particle-bubbles"></div>
        <div class="particle-field particle-hex"></div>
        <div class="particle-field particle-dust"></div>
        <div class="grid-haze"></div>
        <div class="scan-line scan-line-a"></div>
        <div class="scan-line scan-line-b"></div>
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="hero-shell">
        <div class="hero-frame">
            <div class="hero-title-row">
                <div class="hero-crescent">&#9790;</div>
                <div class="hero-title">PhishNyx AI</div>
            </div>
            <div class="hero-subtitle">AI-Powered Phishing Detection Simulator</div>
            <div class="badge-row">
                <span class="hero-badge">&#9993; Email Threat Analysis</span>
                <span class="hero-badge">&#9672; Risk Scoring Engine</span>
                <span class="hero-badge">&#11042; SOC-Inspired Workflow</span>
            </div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

left, center, right = st.columns([1.02, 1.36, 0.72], gap="large")

with left:
    st.markdown(
        """
        <div class="panel-frame">
            <div class="panel-title"><span class="panel-icon">&#9993;</span><span>Analyze Suspicious Email</span></div>
            <div class="input-shell">
        """,
        unsafe_allow_html=True,
    )

    if sample_emails:
        st.markdown(
            '<div class="sample-strip-title">Sample Scenarios</div>',
            unsafe_allow_html=True,
        )
        sample_columns = st.columns(len(sample_emails), gap="small")
        for column, sample in zip(sample_columns, sample_emails):
            with column:
                if st.button(sample["label"], key=f'sample_{sample["id"]}', use_container_width=True):
                    st.session_state.sender_input = sample["sender"]
                    st.session_state.subject_input = sample["subject"]
                    st.session_state.body_input = sample["body"]

    sender = st.text_input(
        "Sender Email",
        placeholder="e.g. support@secure-login-paypal.com",
        key="sender_input",
    )
    subject = st.text_input(
        "Email Subject",
        placeholder="e.g. Urgent: Verify Your Account Immediately",
        key="subject_input",
    )
    body = st.text_area(
        "Email Body",
        placeholder="Paste the suspicious email body here...",
        height=220,
        key="body_input",
    )
    analyze_clicked = st.button("Analyze Threat", use_container_width=True)

    st.markdown("</div></div>", unsafe_allow_html=True)

result = None
report_json = None
report_file_name = "phishnyx_report.json"

if analyze_clicked:
    if not body.strip():
        st.warning("Please enter the email body before running the analysis.")
    else:
        result = analyze_email(sender, subject, body)
        report_json = generate_json_report(sender, subject, result)
        report_file_name = build_report_filename(result)
        scan_item = build_recent_scan_item(sender, subject, result)
        st.session_state.recent_scans = [scan_item, *st.session_state.recent_scans[:4]]

score = result["score"] if result else 0
verdict = result["verdict"] if result else "Awaiting Analysis"
flags = result["flags"] if result else []
recommendation = result["recommendation"] if result else (
    "Run the analyzer to generate a triage recommendation based on the submitted email."
)
summary = result.get("summary", "No summary available.") if result else (
    "PhishNyx will score the message, identify phishing indicators, and present a SOC-style triage view."
)
analyst_explanation = build_analyst_explanation(result)
urls_found = result.get("urls_found", []) if result else []
url_score = result.get("url_score", 0) if result else 0
sender_display = sender.strip() if sender.strip() else "Not provided"
shield_class, shield_label = shield_state(score, verdict)

with center:
    st.markdown(
        """
        <div class="panel-frame result-panel">
            <div class="result-header-bar">
                <div class="result-header-title"><span class="result-header-icon">SHLD</span><span>Threat Analysis Result</span></div>
                <div class="result-header-decor"><span></span><span></span><span></span></div>
            </div>
        """,
        unsafe_allow_html=True,
    )

    metric_col_1, metric_col_2, metric_col_3 = st.columns(3, gap="small")

    with metric_col_1:
        st.markdown(
            f"""
            <div class="metric-card result-metric-card score-card">
                <div class="metric-label">Risk Score</div>
                <div class="metric-value">{score}/100</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with metric_col_2:
        st.markdown(
            f"""
            <div class="metric-card result-metric-card verdict-card">
                <div class="metric-label">Verdict</div>
                <div class="metric-value {verdict_class(score)}">{verdict}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with metric_col_3:
        st.markdown(
            f"""
            <div class="metric-card result-metric-card url-risk-card">
                <div class="metric-label">URL Risk</div>
                <div class="metric-value">{url_score}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("</div><div class=\"result-panel-stack\">", unsafe_allow_html=True)

    st.markdown(
        f"""
        <div class="flag-card result-block result-flag-block">
            <div class="block-heading result-block-heading"><span class="heading-pill">ALRT</span><span>Detected Red Flags</span></div>
            {render_flag_items(flags)}
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.markdown(
        f"""
        <div class="recommend-card result-block result-action-block">
            <div class="block-heading result-block-heading"><span class="heading-pill">ACT</span><span>Recommended Action</span></div>
            <div class="analysis-summary">{recommendation}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.markdown(
        f"""
        <div class="recommend-card result-block result-explain-block">
            <div class="block-heading result-block-heading"><span class="heading-pill">WHY</span><span>Analyst Explanation</span></div>
            <div class="analysis-summary">{analyst_explanation}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.markdown(
        f"""
        <div class="url-card result-block result-url-block">
            <div class="block-heading result-block-heading"><span class="heading-pill">URL</span><span>Extracted URLs</span></div>
            {render_url_items(urls_found)}
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        f"""
        <div class="result-summary-strip">
            <span class="summary-label">Sender</span>
            <span class="summary-value">{sender_display}</span>
            <span class="summary-sep"></span>
            <span class="summary-label">Summary</span>
            <span class="summary-copy">{summary}</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown('<div class="export-card result-export-card">', unsafe_allow_html=True)
    if report_json:
        st.download_button(
            "Download Report (.json)",
            data=report_json,
            file_name=report_file_name,
            mime="application/json",
            use_container_width=True,
        )
    else:
        st.button("Download Report (.json)", disabled=True, use_container_width=True)
    st.markdown("</div></div>", unsafe_allow_html=True)

with right:
    st.markdown(
        f"""
        <div class="panel-frame">
            <div class="shield-wrap">
                <div class="shield-ring"></div>
                <div class="shield-core {shield_class}" data-label="{shield_label}"></div>
            </div>
            <div class="sidebar-card">
                <div class="block-heading"><span>CHK</span><span>Phishing Indicators Checked</span></div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        render_indicator_items(flags, url_score, result is not None),
        unsafe_allow_html=True,
    )

    st.markdown(
        """
                <div class="side-copy">
                    The current engine evaluates sender reputation patterns, social engineering language, and URL-based signals to simulate analyst triage.
                </div>
                <div class="sidebar-card recent-scans-card">
                    <div class="block-heading"><span>LOG</span><span>Recent Scans</span></div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        render_recent_scans(st.session_state.recent_scans),
        unsafe_allow_html=True,
    )

    st.markdown(
        """
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
