from core.indicators import (
    URGENT_WORDS,
    CREDENTIAL_WORDS,
    GENERIC_GREETINGS,
    SUSPICIOUS_DOMAINS,
)
from core.scorer import calculate_score, get_verdict
from core.url_checks import analyze_urls


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