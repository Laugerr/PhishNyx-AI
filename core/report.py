import json
from datetime import datetime, timezone
import re


def build_report_payload(
    sender: str,
    subject: str,
    analysis_result: dict,
    display_name: str = "",
    reply_to: str = "",
    return_path: str = "",
    attachment_name: str = "",
    case_metadata: dict | None = None,
) -> dict:
    return {
        "case": case_metadata or {},
        "display_name": display_name.strip() if display_name else "",
        "sender": sender.strip() if sender else "",
        "reply_to": reply_to.strip() if reply_to else "",
        "return_path": return_path.strip() if return_path else "",
        "subject": subject.strip() if subject else "",
        "attachment_name": attachment_name.strip() if attachment_name else "",
        "score": analysis_result.get("score", 0),
        "verdict": analysis_result.get("verdict", "Unknown"),
        "flags": analysis_result.get("flags", []),
        "details": analysis_result.get("details", []),
        "recommendation": analysis_result.get("recommendation", ""),
        "urls_found": analysis_result.get("urls_found", []),
        "url_score": analysis_result.get("url_score", 0),
        "triage_findings": analysis_result.get("triage_findings", []),
        "severity_breakdown": analysis_result.get("severity_breakdown", []),
        "triage_overview": analysis_result.get("triage_overview", ""),
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def generate_json_report(
    sender: str,
    subject: str,
    analysis_result: dict,
    display_name: str = "",
    reply_to: str = "",
    return_path: str = "",
    attachment_name: str = "",
    case_metadata: dict | None = None,
) -> str:
    report_payload = build_report_payload(
        sender,
        subject,
        analysis_result,
        display_name=display_name,
        reply_to=reply_to,
        return_path=return_path,
        attachment_name=attachment_name,
        case_metadata=case_metadata,
    )
    return json.dumps(report_payload, indent=4)


def build_report_filename(analysis_result: dict) -> str:
    verdict = analysis_result.get("verdict", "unknown").lower()
    safe_verdict = re.sub(r"[^a-z0-9]+", "-", verdict).strip("-") or "unknown"
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M")
    return f"phishnyx_{safe_verdict}_{timestamp}.json"
