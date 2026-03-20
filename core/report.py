import json
from datetime import datetime, timezone
import re


def build_report_payload(sender: str, subject: str, analysis_result: dict) -> dict:
    return {
        "sender": sender.strip() if sender else "",
        "subject": subject.strip() if subject else "",
        "score": analysis_result.get("score", 0),
        "verdict": analysis_result.get("verdict", "Unknown"),
        "flags": analysis_result.get("flags", []),
        "details": analysis_result.get("details", []),
        "recommendation": analysis_result.get("recommendation", ""),
        "urls_found": analysis_result.get("urls_found", []),
        "url_score": analysis_result.get("url_score", 0),
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def generate_json_report(sender: str, subject: str, analysis_result: dict) -> str:
    report_payload = build_report_payload(sender, subject, analysis_result)
    return json.dumps(report_payload, indent=4)


def build_report_filename(analysis_result: dict) -> str:
    verdict = analysis_result.get("verdict", "unknown").lower()
    safe_verdict = re.sub(r"[^a-z0-9]+", "-", verdict).strip("-") or "unknown"
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M")
    return f"phishnyx_{safe_verdict}_{timestamp}.json"
