from core.indicators import (
    URGENT_WORDS,
    CREDENTIAL_WORDS,
    GENERIC_GREETINGS,
    SUSPICIOUS_DOMAINS,
)
from core.scorer import calculate_score, get_verdict


def analyze_email(sender, subject, body):
    text = f"{subject} {body}".lower()
    sender_lower = sender.lower() if sender else ""
    flags = []

    if any(word in text for word in URGENT_WORDS):
        flags.append("Urgent language designed to pressure the recipient")

    if any(word in text for word in CREDENTIAL_WORDS):
        flags.append("Credential or account verification request detected")

    if any(greet in text for greet in GENERIC_GREETINGS):
        flags.append("Generic greeting often used in bulk phishing emails")

    if any(domain in sender_lower for domain in SUSPICIOUS_DOMAINS):
        flags.append("Suspicious sender domain pattern detected")

    score = calculate_score(flags)
    verdict = get_verdict(score)

    if score >= 50:
        recommendation = (
            "Do not click links, open attachments, or reply. Verify the sender through an official channel and report the message to the security team."
        )
    elif score >= 25:
        recommendation = (
            "Treat the email with caution. Verify the sender and inspect any links before taking action."
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
        "recommendation": recommendation,
        "summary": summary,
    }