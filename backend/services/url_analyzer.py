import ipaddress
from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "verification",
    "password",
    "payment",
    "billing",
]

SHORTENER_DOMAINS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
]


def is_ip_address(hostname):
    """Check whether hostname is an IP address."""

    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def analyze_url(url):
    """
    Perform static analysis of a URL.

    The URL is NEVER opened or visited.
    """

    if not url:
        return {
            "url": url,
            "url_risk_score": 0,
            "url_findings": ["No URL provided."]
        }

    url = url.strip()

    risk_score = 0
    findings = []

    # -------------------------------------------------
    # Parse URL
    # -------------------------------------------------

    parsed = urlparse(url)

    scheme = parsed.scheme.lower()
    hostname = parsed.hostname or ""
    path = parsed.path.lower()

    # -------------------------------------------------
    # HTTP instead of HTTPS
    # -------------------------------------------------

    if scheme == "http":
        risk_score += 10
        findings.append(
            "URL uses HTTP instead of HTTPS."
        )

    # -------------------------------------------------
    # Raw IP address
    # -------------------------------------------------

    if is_ip_address(hostname):
        risk_score += 20
        findings.append(
            "URL uses a raw IP address instead of a domain name."
        )

    # -------------------------------------------------
    # Subdomain count
    # -------------------------------------------------

    subdomain_count = max(
        len(hostname.split(".")) - 2,
        0
    )

    if subdomain_count >= 3:
        risk_score += 10
        findings.append(
            "URL contains an unusually high number of subdomains."
        )

    # -------------------------------------------------
    # Suspicious keywords
    # -------------------------------------------------

    combined_url_text = f"{hostname}{path}".lower()

    matched_keywords = [
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in combined_url_text
    ]

    if matched_keywords:
        risk_score += 10

        findings.append(
            "URL contains security-sensitive keywords: "
            + ", ".join(matched_keywords)
        )

    # -------------------------------------------------
    # URL shortening
    # -------------------------------------------------

    if hostname.lower() in SHORTENER_DOMAINS:
        risk_score += 10
        findings.append(
            "URL uses a known URL-shortening domain pattern."
        )

    # -------------------------------------------------
    # Unusual characters
    # -------------------------------------------------

    if "@" in url:
        risk_score += 10
        findings.append(
            "URL contains an '@' character that may obscure "
            "the actual destination."
        )

    # -------------------------------------------------
    # Excessive URL length
    # -------------------------------------------------

    if len(url) > 150:
        risk_score += 5
        findings.append(
            "URL is unusually long."
        )

    # -------------------------------------------------
    # HTTPS does not guarantee trust
    # -------------------------------------------------

    if scheme == "https" and not findings:
        findings.append(
            "URL uses HTTPS, but HTTPS alone does not establish "
            "that the destination is trustworthy."
        )

    # -------------------------------------------------
    # Final score
    # -------------------------------------------------

    risk_score = min(risk_score, 100)

    if not findings:
        findings.append(
            "No major static URL anomalies were detected."
        )

    return {
        "url": url,
        "url_risk_score": risk_score,
        "url_findings": findings,
    }