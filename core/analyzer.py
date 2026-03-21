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
    GENERIC_GREETINGS,
    SUSPICIOUS_DOMAINS,
)
from core.scorer import calculate_score, get_verdict
from core.url_checks import analyze_urls


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

    if sender_domain and reply_to_domain and sender_domain != reply_to_domain and suspicious_sender_pattern:
        flags.append("Reply-To mismatch detected")
        details.append("The Reply-To domain does not match the sender domain, which can redirect responses to an attacker-controlled mailbox.")

    if sender_domain and return_path_domain and sender_domain != return_path_domain and suspicious_sender_pattern:
        flags.append("Return-Path mismatch detected")
        details.append("A mismatched Return-Path can indicate spoofing or infrastructure that differs from the visible sender identity.")

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
    }
