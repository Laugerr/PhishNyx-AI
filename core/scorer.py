def calculate_score(flags, url_score=0):
    score = 0

    for flag in flags:
        flag_lower = flag.lower()

        if "urgent language" in flag_lower:
            score += 15
        elif "credential" in flag_lower or "verification request" in flag_lower:
            score += 25
        elif "generic greeting" in flag_lower:
            score += 10
        elif "suspicious sender" in flag_lower or "domain pattern" in flag_lower:
            score += 20
        elif "payment" in flag_lower or "invoice" in flag_lower:
            score += 15
        elif "attachment lure" in flag_lower or "attachment-themed" in flag_lower:
            score += 15
        elif "reply-to mismatch" in flag_lower:
            score += 15
        elif "return-path mismatch" in flag_lower:
            score += 15
        elif "suspicious attachment type" in flag_lower:
            score += 20
        elif "double-extension attachment" in flag_lower:
            score += 20
        elif "display-name impersonation" in flag_lower or "display name impersonation" in flag_lower:
            score += 20
        elif "brand impersonation" in flag_lower:
            score += 15
        elif "shortened url" in flag_lower:
            score += 15
        elif "ip-based url" in flag_lower or "raw ip" in flag_lower:
            score += 25
        elif "multiple urls" in flag_lower:
            score += 10
        elif "suspicious url keyword" in flag_lower:
            score += 10
        else:
            score += 5

    score += url_score
    return min(score, 100)


def get_verdict(score):
    if score < 25:
        return "Low Risk"
    if score < 50:
        return "Suspicious"
    return "Likely Phishing"
