import json
from pathlib import Path
from datetime import datetime, timezone

import streamlit as st

from core.analyzer import analyze_email
from core.report import build_report_filename, generate_json_report


CASE_STATUS_OPTIONS = ["Open", "Needs Review", "Closed"]
CASE_DISPOSITION_OPTIONS = ["Escalate", "Monitor", "Benign", "Block Sender"]


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


def sample_option_label(sample: dict) -> str:
    return f'{sample.get("category", "Scenario")} - {sample["label"]}'


def create_case_id() -> str:
    return f"PNX-{datetime.now().strftime('%y%m%d-%H%M%S')}"


def default_disposition(verdict: str) -> str:
    if verdict == "Likely Phishing":
        return "Escalate"
    if verdict == "Suspicious":
        return "Monitor"
    return "Benign"


def default_status(verdict: str) -> str:
    if verdict == "Likely Phishing":
        return "Open"
    if verdict == "Suspicious":
        return "Needs Review"
    return "Closed"


def build_case_record(sender: str, subject: str, result: dict) -> dict:
    timestamp = datetime.now(timezone.utc)
    return {
        "case_id": create_case_id(),
        "status": default_status(result["verdict"]),
        "disposition": default_disposition(result["verdict"]),
        "created_at": timestamp.isoformat().replace("+00:00", "Z"),
        "display_time": timestamp.strftime("%H:%M"),
        "sender": sender.strip() or "Not provided",
        "subject": subject.strip() or "No subject",
        "verdict": result["verdict"],
        "score": result["score"],
    }


def build_case_metadata(case_record: dict | None) -> dict:
    if not case_record:
        return {}

    return {
        "case_id": case_record.get("case_id", ""),
        "status": case_record.get("status", ""),
        "disposition": case_record.get("disposition", ""),
        "created_at": case_record.get("created_at", ""),
    }


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
        (
            "Header Signals",
            "reply-to mismatch" in flag_text
            or "return-path mismatch" in flag_text
            or "display name impersonation" in flag_text,
            "ALRT",
        ),
        (
            "Attachments",
            "attachment lure" in flag_text
            or "suspicious attachment type" in flag_text
            or "double-extension attachment" in flag_text,
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


def render_header_overview(display_name: str, reply_to: str, return_path: str, attachment_name: str) -> str:
    entries = [
        ("Display Name", display_name or "Not provided"),
        ("Reply-To", reply_to or "Not provided"),
        ("Return-Path", return_path or "Not provided"),
        ("Attachment", attachment_name or "None"),
    ]

    html = ""
    for label, value in entries:
        html += (
            '<div class="header-item">'
            f'<span class="header-key">{label}</span>'
            f'<span class="header-value">{value}</span>'
            "</div>"
        )
    return html


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
            f'<div class="history-case">{item["case_id"]} - {item["status"]} - {item["disposition"]}</div>'
            f'<div class="history-meta">{item["sender"]} &bull; {item["display_time"]}</div>'
            "</div>"
        )
    return html


def render_triage_findings(findings: list[dict]) -> str:
    if not findings:
        return '<div class="status-empty">Priority findings will appear here after an analysis runs.</div>'

    html = ""
    for finding in findings:
        severity = finding.get("severity", "low")
        html += (
            f'<div class="triage-item triage-{severity}">'
            f'<div class="triage-top"><span class="triage-flag">{finding["flag"]}</span>'
            f'<span class="triage-severity">{severity.upper()}</span></div>'
            f'<div class="triage-meta">{finding["why"]}</div>'
            "</div>"
        )
    return html


def render_severity_breakdown(breakdown: list[dict]) -> str:
    if not breakdown:
        return '<div class="status-empty">Category severity will appear here after an analysis runs.</div>'

    html = ""
    for item in breakdown:
        severity = item.get("severity", "low")
        html += (
            f'<div class="severity-row severity-{severity}">'
            f'<span class="severity-label">{item["label"]}</span>'
            f'<span class="severity-badge">{severity.upper()}</span>'
            f'<span class="severity-count">{item["count"]}</span>'
            "</div>"
        )
    return html


def render_case_summary(case_record: dict | None) -> str:
    if not case_record:
        return '<div class="status-empty">A case record will be created after the next analysis runs.</div>'

    rows = [
        ("Case ID", case_record["case_id"]),
        ("Created", case_record["created_at"].replace("T", " ").replace("Z", " UTC")),
        ("Status", case_record["status"]),
        ("Disposition", case_record["disposition"]),
    ]

    html = ""
    for label, value in rows:
        html += (
            '<div class="case-row">'
            f'<span class="case-key">{label}</span>'
            f'<span class="case-value">{value}</span>'
            "</div>"
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
if "display_name_input" not in st.session_state:
    st.session_state.display_name_input = ""
if "reply_to_input" not in st.session_state:
    st.session_state.reply_to_input = ""
if "return_path_input" not in st.session_state:
    st.session_state.return_path_input = ""
if "attachment_name_input" not in st.session_state:
    st.session_state.attachment_name_input = ""
if "recent_scans" not in st.session_state:
    st.session_state.recent_scans = []
if "selected_sample_id" not in st.session_state:
    st.session_state.selected_sample_id = sample_emails[0]["id"] if sample_emails else None
if "latest_result" not in st.session_state:
    st.session_state.latest_result = None
if "current_case" not in st.session_state:
    st.session_state.current_case = None
if "case_status" not in st.session_state:
    st.session_state.case_status = CASE_STATUS_OPTIONS[0]
if "case_disposition" not in st.session_state:
    st.session_state.case_disposition = CASE_DISPOSITION_OPTIONS[1]

valid_sample_ids = {sample["id"] for sample in sample_emails}
if sample_emails and st.session_state.selected_sample_id not in valid_sample_ids:
    st.session_state.selected_sample_id = sample_emails[0]["id"]

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
        sample_lookup = {sample["id"]: sample for sample in sample_emails}
        default_sample_index = 0
        if st.session_state.selected_sample_id in sample_lookup:
            default_sample_index = next(
                index
                for index, sample in enumerate(sample_emails)
                if sample["id"] == st.session_state.selected_sample_id
            )

        selected_sample_id = st.selectbox(
            "Choose a sample scenario",
            options=[sample["id"] for sample in sample_emails],
            index=default_sample_index,
            format_func=lambda sample_id: sample_option_label(sample_lookup[sample_id]),
            key="selected_sample_id",
        )
        selected_sample = sample_lookup[selected_sample_id]
        st.markdown(
            f'<div class="sample-summary">{selected_sample.get("summary", "")}</div>',
            unsafe_allow_html=True,
        )
        if st.button("Load Selected Sample", key="load_selected_sample", use_container_width=True):
            st.session_state.display_name_input = selected_sample.get("display_name", "")
            st.session_state.sender_input = selected_sample["sender"]
            st.session_state.reply_to_input = selected_sample.get("reply_to", "")
            st.session_state.return_path_input = selected_sample.get("return_path", "")
            st.session_state.subject_input = selected_sample["subject"]
            st.session_state.attachment_name_input = selected_sample.get("attachment_name", "")
            st.session_state.body_input = selected_sample["body"]

    header_col_1, header_col_2 = st.columns(2, gap="small")

    with header_col_1:
        display_name = st.text_input(
            "Display Name",
            placeholder="e.g. Microsoft 365 Security",
            key="display_name_input",
        )
    with header_col_2:
        sender = st.text_input(
            "Sender Email",
            placeholder="e.g. support@secure-login-paypal.com",
            key="sender_input",
        )

    routing_col_1, routing_col_2 = st.columns(2, gap="small")

    with routing_col_1:
        reply_to = st.text_input(
            "Reply-To",
            placeholder="e.g. response@review-center.com",
            key="reply_to_input",
        )
    with routing_col_2:
        return_path = st.text_input(
            "Return-Path",
            placeholder="e.g. bounce@mailer.example",
            key="return_path_input",
        )

    subject = st.text_input(
        "Email Subject",
        placeholder="e.g. Urgent: Verify Your Account Immediately",
        key="subject_input",
    )
    attachment_name = st.text_input(
        "Attachment Name",
        placeholder="e.g. Invoice_Review.html",
        key="attachment_name_input",
    )
    body = st.text_area(
        "Email Body",
        placeholder="Paste the suspicious email body here...",
        height=220,
        key="body_input",
    )
    analyze_clicked = st.button("Analyze Threat", use_container_width=True)

    st.markdown("</div></div>", unsafe_allow_html=True)

if analyze_clicked:
    if not body.strip():
        st.warning("Please enter the email body before running the analysis.")
    else:
        result = analyze_email(
            sender,
            subject,
            body,
            display_name=display_name,
            reply_to=reply_to,
            return_path=return_path,
            attachment_name=attachment_name,
        )
        case_record = build_case_record(sender, subject, result)
        st.session_state.latest_result = result
        st.session_state.current_case = case_record
        st.session_state.case_status = case_record["status"]
        st.session_state.case_disposition = case_record["disposition"]
        st.session_state.recent_scans = [case_record, *st.session_state.recent_scans[:7]]

result = st.session_state.latest_result
current_case = st.session_state.current_case

if current_case:
    current_case["status"] = st.session_state.case_status
    current_case["disposition"] = st.session_state.case_disposition
    if st.session_state.recent_scans:
        for index, item in enumerate(st.session_state.recent_scans):
            if item["case_id"] == current_case["case_id"]:
                st.session_state.recent_scans[index] = current_case.copy()
                break

case_metadata = build_case_metadata(current_case)
report_json = None
report_file_name = "phishnyx_report.json"

if result:
    report_json = generate_json_report(
        sender,
        subject,
        result,
        display_name=display_name,
        reply_to=reply_to,
        return_path=return_path,
        attachment_name=attachment_name,
        case_metadata=case_metadata,
    )
    report_file_name = build_report_filename(result)

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
triage_findings = result.get("triage_findings", []) if result else []
severity_breakdown = result.get("severity_breakdown", []) if result else []
triage_overview = result.get("triage_overview", "Run the analyzer to generate category-level triage priorities.") if result else (
    "Run the analyzer to generate category-level triage priorities."
)
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

    case_col_1, case_col_2 = st.columns([1.18, 0.82], gap="small")

    with case_col_1:
        st.markdown(
            f"""
            <div class="recommend-card result-block result-case-block">
                <div class="block-heading result-block-heading"><span class="heading-pill">CASE</span><span>Case Record</span></div>
                {render_case_summary(current_case)}
            </div>
            """,
            unsafe_allow_html=True,
        )

    with case_col_2:
        st.markdown(
            """
            <div class="url-card result-block result-case-controls">
                <div class="block-heading result-block-heading"><span class="heading-pill">FLOW</span><span>Case Workflow</span></div>
            """,
            unsafe_allow_html=True,
        )
        st.selectbox(
            "Case Status",
            CASE_STATUS_OPTIONS,
            key="case_status",
            disabled=current_case is None,
        )
        st.selectbox(
            "Disposition",
            CASE_DISPOSITION_OPTIONS,
            key="case_disposition",
            disabled=current_case is None,
        )
        st.markdown("</div>", unsafe_allow_html=True)

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

    triage_col_1, triage_col_2 = st.columns(2, gap="small")

    with triage_col_1:
        st.markdown(
            f"""
            <div class="recommend-card result-block result-triage-block">
                <div class="block-heading result-block-heading"><span class="heading-pill">TRI</span><span>Triage Priorities</span></div>
                <div class="analysis-summary triage-overview">{triage_overview}</div>
                {render_triage_findings(triage_findings)}
            </div>
            """,
            unsafe_allow_html=True,
        )

    with triage_col_2:
        st.markdown(
            f"""
            <div class="url-card result-block result-severity-block">
                <div class="block-heading result-block-heading"><span class="heading-pill">SEV</span><span>Severity by Category</span></div>
                {render_severity_breakdown(severity_breakdown)}
            </div>
            """,
            unsafe_allow_html=True,
        )

    context_col_1, context_col_2 = st.columns(2, gap="small")

    with context_col_1:
        st.markdown(
            f"""
            <div class="url-card result-block result-header-block">
                <div class="block-heading result-block-heading"><span class="heading-pill">HDR</span><span>Header &amp; Attachment Context</span></div>
                {render_header_overview(display_name, reply_to, return_path, attachment_name)}
            </div>
            """,
            unsafe_allow_html=True,
        )

    with context_col_2:
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
