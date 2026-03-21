from core.indicators import (
    URGENT_WORDS,
    CREDENTIAL_WORDS,
    PAYMENT_WORDS,
    ATTACHMENT_WORDS,
    HIGH_RISK_ATTACHMENT_PHRASES,
    SUSPICIOUS_ATTACHMENT_KEYWORDS,
    ARCHIVE_LURE_TERMS,
    BENIGN_ATTACHMENT_EXTENSIONS,
    SUSPICIOUS_ATTACHMENT_EXTENSIONS,
    SUSPICIOUS_BRANDS,
    FREE_MAIL_DOMAINS,
    INTERNAL_DOMAINS,
    GENERIC_GREETINGS,
    SUSPICIOUS_DOMAINS,
)
from core.scorer import calculate_score, get_verdict
from core.url_checks import analyze_urls


SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def has_display_name_mismatch(display_name: str, sender: str) -> bool:
    if not display_name or not sender or "@" not in sender:
        return False

    display_tokens = [
        "".join(ch for ch in token.lower() if ch.isalnum())
        for token in display_name.split()
    ]
    display_tokens = [token for token in display_tokens if token]
    normalized_name = "".join(ch for ch in display_name.lower() if ch.isalnum())
    local_part = sender.lower().split("@", 1)[0]
    normalized_local = "".join(ch for ch in local_part if ch.isalnum())

    if not normalized_name or not normalized_local:
        return False

    overlap = any(token in normalized_local for token in display_tokens)
    return normalized_name not in normalized_local and not overlap


def extract_email_domain(value: str) -> str:
    if not value or "@" not in value:
        return ""

    email_value = value.strip().lower()
    if "<" in email_value and ">" in email_value:
        email_value = email_value.split("<", 1)[1].split(">", 1)[0].strip()

    return email_value.split("@", 1)[1] if "@" in email_value else ""


def is_free_mail_domain(domain: str) -> bool:
    return domain in FREE_MAIL_DOMAINS


def is_internal_domain(domain: str) -> bool:
    return domain in INTERNAL_DOMAINS or domain.endswith(".local")


def has_trusted_brand_display_name(display_name: str) -> bool:
    lowered = display_name.lower().strip()
    return any(brand in lowered for brand in SUSPICIOUS_BRANDS)


def is_unrelated_brand_domain(domain: str, display_name: str) -> bool:
    if not domain or not has_trusted_brand_display_name(display_name):
        return False

    lowered_domain = domain.lower()
    return not any(brand.replace(" ", "") in lowered_domain or brand in lowered_domain for brand in SUSPICIOUS_BRANDS)


def has_double_extension(filename: str) -> bool:
    if not filename or "." not in filename:
        return False

    parts = [part for part in filename.lower().split(".") if part]
    return len(parts) >= 3


def has_suspicious_attachment_type(filename: str) -> bool:
    lowered = filename.lower().strip()
    return any(lowered.endswith(extension) for extension in SUSPICIOUS_ATTACHMENT_EXTENSIONS)


def has_benign_attachment_type(filename: str) -> bool:
    lowered = filename.lower().strip()
    return any(lowered.endswith(extension) for extension in BENIGN_ATTACHMENT_EXTENSIONS)


def has_high_risk_attachment_phrase(text: str) -> bool:
    return any(phrase in text for phrase in HIGH_RISK_ATTACHMENT_PHRASES)


def has_suspicious_attachment_name(filename: str) -> bool:
    lowered = filename.lower().strip()
    return any(keyword in lowered for keyword in SUSPICIOUS_ATTACHMENT_KEYWORDS)


def has_archive_lure(text: str, filename: str) -> bool:
    lowered_filename = filename.lower().strip()
    archive_extension = lowered_filename.endswith(".zip") or lowered_filename.endswith(".rar")
    return archive_extension or any(term in text for term in ARCHIVE_LURE_TERMS)


def has_payment_pressure(text: str) -> bool:
    payment_hit = any(word in text for word in PAYMENT_WORDS)
    if not payment_hit:
        return False

    suspicious_context = any(word in text for word in URGENT_WORDS) or any(
        word in text for word in CREDENTIAL_WORDS
    )
    payment_pressure_terms = [
        "process today",
        "complete the transfer",
        "payment overdue",
        "send confirmation",
        "beneficiary details",
        "confidential wire",
    ]
    return suspicious_context or any(term in text for term in payment_pressure_terms)


def build_triage_finding(flag: str) -> dict:
    flag_lower = flag.lower()

    if "credential" in flag_lower or "verification request" in flag_lower:
        return {
            "flag": flag,
            "category": "content",
            "severity": "critical",
            "priority": 95,
            "why": "Credential theft language is one of the clearest indicators of phishing intent.",
        }
    if "raw ip" in flag_lower or "ip-based url" in flag_lower:
        return {
            "flag": flag,
            "category": "urls",
            "severity": "critical",
            "priority": 92,
            "why": "Direct IP links bypass normal brand and domain trust signals and are high-risk in email.",
        }
    if "suspicious attachment type" in flag_lower or "double-extension attachment" in flag_lower:
        return {
            "flag": flag,
            "category": "attachments",
            "severity": "high",
            "priority": 88,
            "why": "Executable or disguised attachments are commonly used to deliver malware or credential harvesters.",
        }
    if "reply-to mismatch" in flag_lower or "return-path mismatch" in flag_lower:
        return {
            "flag": flag,
            "category": "headers",
            "severity": "high",
            "priority": 84,
            "why": "Header routing mismatches can indicate spoofing or attacker-controlled reply paths.",
        }
    if "trusted brand display name" in flag_lower or "display-name impersonation" in flag_lower:
        return {
            "flag": flag,
            "category": "headers",
            "severity": "high",
            "priority": 82,
            "why": "Sender identity inconsistencies often signal impersonation meant to borrow trust.",
        }
    if "brand impersonation" in flag_lower or "suspicious sender" in flag_lower:
        return {
            "flag": flag,
            "category": "sender",
            "severity": "high",
            "priority": 80,
            "why": "Brand and sender anomalies often indicate a spoofed origin or impersonation attempt.",
        }
    if "shortened url" in flag_lower or "suspicious url keyword" in flag_lower:
        return {
            "flag": flag,
            "category": "urls",
            "severity": "medium",
            "priority": 70,
            "why": "Obfuscated or phishing-themed links increase the chance of redirecting users to a malicious site.",
        }
    if "attachment lure" in flag_lower or "archive-style attachment lure" in flag_lower:
        return {
            "flag": flag,
            "category": "attachments",
            "severity": "medium",
            "priority": 68,
            "why": "Social engineering around opening attachments is a common path to malware delivery.",
        }
    if "urgent language" in flag_lower or "payment" in flag_lower or "invoice" in flag_lower:
        return {
            "flag": flag,
            "category": "content",
            "severity": "medium",
            "priority": 65,
            "why": "Pressure tactics are used to shorten review time and push risky user actions.",
        }
    if "multiple urls" in flag_lower:
        return {
            "flag": flag,
            "category": "urls",
            "severity": "medium",
            "priority": 60,
            "why": "Link-heavy emails can be used for link spraying or to create urgency through multiple destinations.",
        }
    if "generic greeting" in flag_lower:
        return {
            "flag": flag,
            "category": "content",
            "severity": "low",
            "priority": 40,
            "why": "Generic greetings are weaker signals, but they are common in mass-targeted phishing emails.",
        }

    return {
        "flag": flag,
        "category": "content",
        "severity": "low",
        "priority": 35,
        "why": "This finding contributes to analyst caution under the current phishing rule set.",
    }


def build_severity_breakdown(findings: list[dict]) -> list[dict]:
    labels = {
        "content": "Content",
        "sender": "Sender",
        "headers": "Headers",
        "attachments": "Attachments",
        "urls": "URLs",
    }
    grouped = {
        key: {"category": key, "label": label, "count": 0, "severity": "low"}
        for key, label in labels.items()
    }

    for finding in findings:
        category = finding["category"]
        entry = grouped[category]
        entry["count"] += 1
        if SEVERITY_ORDER[finding["severity"]] > SEVERITY_ORDER[entry["severity"]]:
            entry["severity"] = finding["severity"]

    return [grouped[key] for key in labels]


def build_triage_overview(findings: list[dict], verdict: str) -> str:
    if not findings:
        return (
            "No categories escalated beyond low concern. Continue standard verification hygiene, "
            "but the current rules did not identify strong triage priorities."
        )

    highest = max(findings, key=lambda item: (SEVERITY_ORDER[item["severity"]], item["priority"]))
    categories = []
    for finding in findings:
        if finding["category"] not in categories:
            categories.append(finding["category"])

    lead_categories = ", ".join(category.capitalize() for category in categories[:2])
    return (
        f"{verdict} triage was driven primarily by {lead_categories} signals. "
        f"Top concern: {highest['flag']}"
    )


def analyze_email(sender, subject, body, display_name="", reply_to="", return_path="", attachment_name=""):
    text = f"{subject} {body}".lower()
    sender_lower = sender.lower().strip() if sender else ""
    display_name_lower = display_name.lower().strip() if display_name else ""
    flags = []
    details = []

    if any(word in text for word in URGENT_WORDS):
        flags.append("Urgent language designed to pressure the recipient")
        details.append("Urgency is commonly used in phishing to reduce critical thinking time.")

    if any(word in text for word in CREDENTIAL_WORDS):
        flags.append("Credential or account verification request detected")
        details.append("Requests for passwords, logins, or account confirmation are strong phishing indicators.")

    if any(greet in text for greet in GENERIC_GREETINGS):
        flags.append("Generic greeting often used in bulk phishing emails")
        details.append("Non-personalized greetings are common in mass phishing campaigns.")

    if any(domain in sender_lower for domain in SUSPICIOUS_DOMAINS):
        flags.append("Suspicious sender domain pattern detected")
        details.append("The sender address contains domain patterns often used in impersonation or phishing.")

    if has_payment_pressure(text):
        flags.append("Payment or invoice pressure language detected")
        details.append("Unexpected payment or invoice language is often used in business email compromise and billing scams.")

    attachment_lure_detected = any(word in text for word in ATTACHMENT_WORDS)
    suspicious_attachment_context = (
        has_high_risk_attachment_phrase(text)
        or has_suspicious_attachment_type(attachment_name)
        or has_double_extension(attachment_name)
        or any(word in text for word in URGENT_WORDS)
        or any(word in text for word in CREDENTIAL_WORDS)
    )
    if attachment_lure_detected and suspicious_attachment_context:
        flags.append("Attachment lure language detected")
        details.append("Phishing emails frequently pressure recipients to open attached files or documents.")

    if has_display_name_mismatch(display_name, sender):
        flags.append("Display name impersonation pattern detected")
        details.append("The sender display name does not align cleanly with the underlying email address.")

    suspicious_sender_pattern = any(domain in sender_lower for domain in SUSPICIOUS_DOMAINS)
    if any(brand in text for brand in SUSPICIOUS_BRANDS) and suspicious_sender_pattern:
        flags.append("Brand impersonation cues detected")
        details.append("Brand references combined with suspicious sender patterns can indicate impersonation attempts.")

    if display_name_lower and any(brand in display_name_lower for brand in SUSPICIOUS_BRANDS) and suspicious_sender_pattern:
        flags.append("Brand impersonation cues detected")
        details.append("The display name references a trusted brand while the sender domain appears suspicious.")

    sender_domain = extract_email_domain(sender)
    reply_to_domain = extract_email_domain(reply_to)
    return_path_domain = extract_email_domain(return_path)

    if display_name_lower and is_internal_domain(sender_domain) and has_display_name_mismatch(display_name, sender):
        flags.append("Internal display-name mismatch detected")
        details.append("An internal-looking sender uses a display name that does not align with the visible mailbox identity.")

    if sender_domain and reply_to_domain and sender_domain != reply_to_domain and suspicious_sender_pattern:
        flags.append("Reply-To mismatch detected")
        details.append("The Reply-To domain does not match the sender domain, which can redirect responses to an attacker-controlled mailbox.")

    if sender_domain and return_path_domain and sender_domain != return_path_domain and suspicious_sender_pattern:
        flags.append("Return-Path mismatch detected")
        details.append("A mismatched Return-Path can indicate spoofing or infrastructure that differs from the visible sender identity.")

    if reply_to_domain and is_free_mail_domain(reply_to_domain) and sender_domain and sender_domain != reply_to_domain:
        flags.append("Free-mail Reply-To detected")
        details.append("A corporate-looking email that routes replies to a free-mail provider can indicate impersonation or reply-hijacking behavior.")

    if display_name_lower and sender_domain and is_unrelated_brand_domain(sender_domain, display_name):
        flags.append("Trusted brand display name on unrelated domain detected")
        details.append("The display name references a trusted brand, but the sender domain does not align with that brand identity.")

    if attachment_name:
        if has_suspicious_attachment_type(attachment_name):
            flags.append("Suspicious attachment type detected")
            details.append("The attachment extension is commonly abused in phishing and malware delivery campaigns.")

        if has_double_extension(attachment_name):
            flags.append("Double-extension attachment naming detected")
            details.append("Multiple file extensions can be used to disguise the true nature of an attachment.")

        if has_suspicious_attachment_name(attachment_name) and not has_benign_attachment_type(attachment_name):
            flags.append("Suspicious attachment filename pattern detected")
            details.append("The attachment name uses phishing-associated terms often seen in credential, billing, or malware lures.")

        if has_archive_lure(text, attachment_name):
            flags.append("Archive-style attachment lure detected")
            details.append("Archive-based delivery or archive-style instructions are commonly used to stage malicious payloads.")

        if has_benign_attachment_type(attachment_name) and not suspicious_attachment_context:
            details.append("The attachment type appears common for normal business communication and did not independently raise the score.")

    url_result = analyze_urls(body)
    if url_result["flags"]:
        flags.extend(url_result["flags"])
        details.extend(url_result["details"])

    flags = list(dict.fromkeys(flags))
    details = list(dict.fromkeys(details))

    score = calculate_score(flags, url_score=url_result["score"])
    verdict = get_verdict(score)
    triage_findings = sorted(
        [build_triage_finding(flag) for flag in flags],
        key=lambda item: (item["priority"], SEVERITY_ORDER[item["severity"]]),
        reverse=True,
    )
    severity_breakdown = build_severity_breakdown(triage_findings)
    triage_overview = build_triage_overview(triage_findings, verdict)

    if score >= 50:
        recommendation = (
            "Do not click links, open attachments, or reply. Verify the sender through an official channel and report the message to the security team."
        )
    elif score >= 25:
        recommendation = (
            "Treat the email with caution. Verify the sender and inspect any links carefully before taking action."
        )
    else:
        recommendation = (
            "Low immediate risk based on current rules, but continue to verify unfamiliar messages before interacting."
        )

    if flags:
        summary = (
            f"The message was classified as {verdict.lower()} because the analyzer detected "
            f"{len(flags)} indicator(s) associated with phishing or social engineering behavior."
        )
    else:
        summary = (
            "The current rules did not identify strong phishing indicators in the submitted content."
        )

    return {
        "score": score,
        "verdict": verdict,
        "flags": flags,
        "details": details,
        "recommendation": recommendation,
        "summary": summary,
        "urls_found": url_result["urls"],
        "url_score": url_result["score"],
        "triage_findings": triage_findings[:3],
        "severity_breakdown": severity_breakdown,
        "triage_overview": triage_overview,
    }
