import re
from urllib.parse import urlparse

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "shorturl.at",
}

SUSPICIOUS_URL_KEYWORDS = [
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "reset",
    "signin",
    "confirm",
    "wallet",
    "banking",
    "password",
]

IP_URL_PATTERN = re.compile(
    r"^(?:http[s]?://)?(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/.*)?$",
    re.IGNORECASE,
)

URL_PATTERN = re.compile(
    r"""(?i)\b((?:https?://|www\.)[^\s<>"']+)"""
)


def extract_urls(text: str) -> list[str]:
    if not text:
        return []

    urls = URL_PATTERN.findall(text)
    cleaned = []

    for url in urls:
        normalized = url.strip(".,);]}>\"'")
        if normalized.startswith("www."):
            normalized = f"http://{normalized}"
        cleaned.append(normalized)

    return cleaned


def get_domain(url: str) -> str:
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().strip()
        if domain.startswith("www."):
            domain = domain[4:]
        return domain
    except Exception:
        return ""


def is_shortener(domain: str) -> bool:
    return domain in SHORTENERS


def is_ip_url(url: str) -> bool:
    return bool(IP_URL_PATTERN.match(url))


def has_suspicious_keywords(url: str) -> bool:
    lowered = url.lower()
    return any(keyword in lowered for keyword in SUSPICIOUS_URL_KEYWORDS)


def analyze_urls(text: str) -> dict:
    urls = extract_urls(text)
    flags = []
    details = []

    if not urls:
        return {
            "urls": [],
            "flags": [],
            "details": [],
            "score": 0,
        }

    score = 0

    if len(urls) >= 3:
        flags.append("Multiple URLs detected in the email body")
        details.append(f"Found {len(urls)} URLs, which may indicate phishing or link spraying.")
        score += 10

    for url in urls:
        domain = get_domain(url)

        if is_ip_url(url):
            flags.append(f"Raw IP-based URL detected: {url}")
            details.append("Phishing emails may use direct IP links to avoid domain-based trust signals.")
            score += 25

        if domain and is_shortener(domain):
            flags.append(f"Shortened URL detected: {domain}")
            details.append("Shortened links can obscure the real destination.")
            score += 15

        if has_suspicious_keywords(url):
            flags.append(f"Suspicious URL keyword pattern detected: {url}")
            details.append("The URL contains phishing-associated words such as login, verify, or reset.")
            score += 10

    unique_flags = list(dict.fromkeys(flags))
    unique_details = list(dict.fromkeys(details))

    return {
        "urls": urls,
        "flags": unique_flags,
        "details": unique_details,
        "score": min(score, 40),
    }