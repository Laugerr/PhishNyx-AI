from core.indicators import (
    URGENT_WORDS,
    CREDENTIAL_WORDS,
    PAYMENT_WORDS,
    ATTACHMENT_WORDS,
    SUSPICIOUS_BRANDS,
    GENERIC_GREETINGS,
    SUSPICIOUS_DOMAINS,
)
from core.scorer import calculate_score, get_verdict
from core.url_checks import analyze_urls


def has_display_name_mismatch(sender: str) -> bool:
    if not sender or "<" not in sender or ">" not in sender:
        return False

    display_name = sender.split("<", 1)[0].strip().lower()
    email_part = sender.split("<", 1)[1].split(">", 1)[0].strip().lower()
    return bool(display_name and email_part and display_name not in email_part)


def analyze_email(sender, subject, body):
    text = f"{subject} {body}".lower()
    sender_lower = sender.lower().strip() if sender else ""
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

    if any(word in text for word in PAYMENT_WORDS):
        flags.append("Payment or invoice pressure language detected")
        details.append("Unexpected payment or invoice language is often used in business email compromise and billing scams.")

    if any(word in text for word in ATTACHMENT_WORDS):
        flags.append("Attachment lure language detected")
        details.append("Phishing emails frequently pressure recipients to open attached files or documents.")

    if has_display_name_mismatch(sender):
        flags.append("Display name impersonation pattern detected")
        details.append("The sender display name does not align cleanly with the underlying email address.")

    if any(brand in text for brand in SUSPICIOUS_BRANDS) and any(domain in sender_lower for domain in SUSPICIOUS_DOMAINS):
        flags.append("Brand impersonation cues detected")
        details.append("Brand references combined with suspicious sender patterns can indicate impersonation attempts.")

    url_result = analyze_urls(body)
    if url_result["flags"]:
        flags.extend(url_result["flags"])
        details.extend(url_result["details"])

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
