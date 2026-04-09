import ipaddress
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
    except ValueError:
        return ""


def is_shortener(domain: str) -> bool:
    return domain in SHORTENERS


def is_ip_url(url: str) -> bool:
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        host = parsed.hostname
        if not host:
            return False
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


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

    ip_urls = []
    shortened_domains = []
    keyword_urls = []

    for url in urls:
        domain = get_domain(url)

        if is_ip_url(url):
            ip_urls.append(url)

        if domain and is_shortener(domain) and domain not in shortened_domains:
            shortened_domains.append(domain)

        if has_suspicious_keywords(url):
            keyword_urls.append(url)

    if ip_urls:
        sample = ip_urls[0]
        label = f"Raw IP-based URL detected: {sample}" if len(ip_urls) == 1 else f"Raw IP-based URLs detected ({len(ip_urls)} links)"
        flags.append(label)
        details.append("Phishing emails may use direct IP links to avoid domain-based trust signals.")
        score += 25

    if shortened_domains:
        sample = shortened_domains[0]
        label = f"Shortened URL detected: {sample}" if len(shortened_domains) == 1 else f"Shortened URLs detected ({len(shortened_domains)} links)"
        flags.append(label)
        details.append("Shortened links can obscure the real destination.")
        score += 15

    if keyword_urls:
        label = f"Suspicious URL keyword pattern detected: {keyword_urls[0]}" if len(keyword_urls) == 1 else f"Suspicious URL keyword patterns detected ({len(keyword_urls)} links)"
        flags.append(label)
        details.append("URLs contain phishing-associated words such as login, verify, or reset.")
        score += 10

    return {
        "urls": urls,
        "flags": flags,
        "details": details,
        "score": min(score, 40),
    }