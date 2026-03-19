import streamlit as st
from pathlib import Path
from core.analyzer import analyze_email


def load_css(file_name: str) -> None:
    css_path = Path(file_name)
    if css_path.exists():
        with open(css_path, "r", encoding="utf-8") as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)


def verdict_class(score: int) -> str:
    if score < 25:
        return "risk-low"
    if score < 50:
        return "risk-mid"
    return "risk-high"


def render_flag_items(flags: list[str]) -> str:
    if not flags:
        return ""
    html = ""
    for index, flag in enumerate(flags, start=1):
        html += f'<div class="flag-item flag-delay-{index}">• {flag}</div>'
    return html


def render_url_items(urls: list[str]) -> str:
    if not urls:
        return '<div class="info-text">No URLs found in the submitted email body.</div>'
    html = ""
    for url in urls:
        html += f'<div class="check-item">🔗 {url}</div>'
    return html


st.set_page_config(
    page_title="PhishNyx AI",
    page_icon="🌑",
    layout="wide",
    initial_sidebar_state="collapsed",
)

load_css("styles.css")

st.markdown(
    """
    <div class="hero-box">
        <div class="hero-orb hero-orb-1"></div>
        <div class="hero-orb hero-orb-2"></div>
        <div class="hero-content">
            <div class="hero-title">🌑 PhishNyx AI</div>
            <div class="hero-subtitle">
                AI-powered phishing detection simulator built to uncover suspicious email behavior,
                score threat likelihood, and support SOC-style triage.
            </div>
            <div class="badge-row">
                <span class="hero-badge">Email Threat Analysis</span>
                <span class="hero-badge">Interactive UI</span>
                <span class="hero-badge">Risk Scoring Engine</span>
                <span class="hero-badge">SOC-Inspired Workflow</span>
            </div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

left, right = st.columns([1.25, 0.75], gap="large")

with left:
    st.markdown('<div class="glass-card input-card">', unsafe_allow_html=True)
    st.markdown('<div class="section-title">📥 Analyze a Suspicious Email</div>', unsafe_allow_html=True)

    sender = st.text_input(
        "Sender Email",
        placeholder="e.g. support@secure-login-paypal.com",
    )

    subject = st.text_input(
        "Email Subject",
        placeholder="e.g. Urgent: Verify Your Account Immediately",
    )

    body = st.text_area(
        "Email Body",
        placeholder="Paste the suspicious email body here...",
        height=280,
    )

    analyze_clicked = st.button("🔍 Analyze Threat", use_container_width=True)
    st.markdown("</div>", unsafe_allow_html=True)

with right:
    st.markdown(
        """
        <div class="glass-card side-card">
            <div class="section-title">🧠 What PhishNyx Checks</div>
            <div class="info-text">
                The current rule-based engine looks for high-signal phishing indicators commonly seen in suspicious email campaigns.
            </div>
            <div class="check-list">
                <div class="check-item">⚡ Urgent or coercive language</div>
                <div class="check-item">🔐 Credential harvesting phrases</div>
                <div class="check-item">👤 Generic greetings</div>
                <div class="check-item">🌐 Suspicious sender domains</div>
                <div class="check-item">🔗 Risky URLs and shortened links</div>
            </div>
            <div class="info-foot">
                Next upgrades: JSON export, AI explanations, downloadable reports, and training mode.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

if analyze_clicked:
    if not body.strip():
        st.warning("Please enter the email body before running the analysis.")
    else:
        result = analyze_email(sender, subject, body)
        score = result["score"]
        verdict = result["verdict"]
        flags = result["flags"]
        recommendation = result["recommendation"]
        summary = result.get("summary", "No summary available.")
        sender_display = sender.strip() if sender.strip() else "Not provided"
        urls_found = result.get("urls_found", [])
        url_score = result.get("url_score", 0)

        st.markdown('<div class="results-wrap">', unsafe_allow_html=True)

        c1, c2, c3 = st.columns(3, gap="medium")

        with c1:
            st.markdown(
                f"""
                <div class="metric-card floating-card">
                    <div class="metric-label">Risk Score</div>
                    <div class="metric-value">{score}/100</div>
                    <div class="metric-sub">Phishing likelihood estimate</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        with c2:
            st.markdown(
                f"""
                <div class="metric-card floating-card">
                    <div class="metric-label">Verdict</div>
                    <div class="metric-value {verdict_class(score)}">{verdict}</div>
                    <div class="metric-sub">{len(flags)} red flag(s) detected</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        with c3:
            st.markdown(
                f"""
                <div class="metric-card floating-card">
                    <div class="metric-label">URL Risk Contribution</div>
                    <div class="metric-value">{url_score}</div>
                    <div class="metric-sub">{len(urls_found)} URL(s) extracted</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown('<div class="progress-label">Threat Level</div>', unsafe_allow_html=True)
        st.progress(score)

        col_a, col_b = st.columns([1.1, 0.9], gap="large")

        with col_a:
            st.markdown(
                f"""
                <div class="glass-card result-card">
                    <div class="section-title">🛡️ Threat Triage Result</div>
                    <div class="result-summary">
                        Final verdict:
                        <span class="{verdict_class(score)}">{verdict}</span>
                    </div>
                    <div class="analysis-summary">{summary}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            if flags:
                st.markdown(
                    f"""
                    <div class="glass-card flag-card">
                        <div class="section-title">🚨 Detected Red Flags</div>
                        {render_flag_items(flags)}
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            else:
                st.success("No strong phishing indicators were detected by the current rule set.")

        with col_b:
            st.markdown(
                f"""
                <div class="glass-card recommend-card">
                    <div class="section-title">💡 Recommended Action</div>
                    <div class="recommend-box">{recommendation}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            st.markdown(
                f"""
                <div class="glass-card">
                    <div class="section-title">🔗 Extracted URLs</div>
                    {render_url_items(urls_found)}
                    <div class="info-foot" style="margin-top: 16px;">
                        URL analysis is now part of the phishing score and highlights hidden link-based risks.
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown("</div>", unsafe_allow_html=True)