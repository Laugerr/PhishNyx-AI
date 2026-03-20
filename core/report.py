import json
from datetime import datetime, timezone


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
