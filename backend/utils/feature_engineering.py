import re

from backend.utils.preprocessor import (
    extract_urls,
    extract_sender_domain,
    extract_attachment_extension,
    calculate_uppercase_ratio,
    count_exclamation_marks,
)

from backend.services.url_analyzer import analyze_url
from backend.services.content_analyzer import analyze_content


def count_subdomains(domain):
    """
    Estimate the number of subdomains in a domain.
    """

    if not domain:
        return 0

    parts = domain.split(".")

    if len(parts) <= 2:
        return 0

    return len(parts) - 2


def is_ip_address(hostname):
    """
    Check whether a hostname is an IPv4 address.
    """

    if not hostname:
        return False

    pattern = r"^\d{1,3}(\.\d{1,3}){3}$"

    return bool(re.match(pattern, hostname))


def extract_hostname(url):
    """
    Extract hostname from a URL.
    """

    from urllib.parse import urlparse

    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def extract_email_features(
    sender,
    subject,
    body,
    attachment_name="",
    urls=None,
):
    """
    Extract structured security features from an email.
    """

    sender = sender or ""
    subject = subject or ""
    body = body or ""

    # Handle missing attachment values from CSV/Excel
    if not isinstance(attachment_name, str):
        attachment_name = ""

    attachment_name = attachment_name.strip()

    # -------------------------------------------------
    # URL extraction
    # -------------------------------------------------

    if urls is None:
        extracted_urls = extract_urls(
            f"{subject} {body}"
        )
    else:
        extracted_urls = urls

    # -------------------------------------------------
    # Content analysis
    # -------------------------------------------------

    content_result = analyze_content(
        subject,
        body
    )

    # -------------------------------------------------
    # URL analysis
    # -------------------------------------------------

    url_results = [
        analyze_url(url)
        for url in extracted_urls
    ]

    # -------------------------------------------------
    # URL features
    # -------------------------------------------------

    suspicious_url_count = sum(
        1
        for result in url_results
        if result.get("url_risk_score", 0) > 0
    )

    has_ip_url = any(
        is_ip_address(
            extract_hostname(url)
        )
        for url in extracted_urls
    )

    shortened_domains = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
    ]

    has_shortened_url_pattern = any(
        any(
            domain in url.lower()
            for domain in shortened_domains
        )
        for url in extracted_urls
    )

    # -------------------------------------------------
    # Sender features
    # -------------------------------------------------

    sender_domain = extract_sender_domain(
        sender
    )

    sender_domain_length = len(
        sender_domain
    )

    subdomain_count = count_subdomains(
        sender_domain
    )

    # -------------------------------------------------
    # Attachment features
    # -------------------------------------------------

    attachment_extension = (
        extract_attachment_extension(
            attachment_name
        )
    )

    suspicious_extensions = [
        "exe",
        "scr",
        "bat",
        "cmd",
        "js",
        "vbs",
        "ps1",
    ]

    suspicious_attachment = (
        attachment_extension
        in suspicious_extensions
    )

    # Double extension
    if len(
        attachment_name.split(".")
    ) >= 3:

        suspicious_attachment = (
            suspicious_attachment
            or attachment_name.lower().endswith(
                tuple(
                    "." + ext
                    for ext in suspicious_extensions
                )
            )
        )

    # -------------------------------------------------
    # Password / personal information indicators
    # -------------------------------------------------

    combined_text = (
        f"{subject} {body}"
    ).lower()

    password_request = any(
        keyword in combined_text
        for keyword in [
            "password",
            "enter your password",
            "provide your password",
            "confirm your password",
        ]
    )

    personal_info_request = any(
        keyword in combined_text
        for keyword in [
            "personal information",
            "date of birth",
            "phone number",
            "address",
            "identity",
            "id proof",
        ]
    )

    # -------------------------------------------------
    # Final feature dictionary
    # -------------------------------------------------

    features = {
        "urgent_keyword_count":
            content_result[
                "urgency_keyword_count"
            ],

        "credential_keyword_count":
            content_result[
                "credential_keyword_count"
            ],

        "financial_keyword_count":
            content_result[
                "financial_keyword_count"
            ],

        "threat_keyword_count":
            content_result[
                "threat_keyword_count"
            ],

        "url_count":
            len(extracted_urls),

        "suspicious_url_count":
            suspicious_url_count,

        "has_ip_url":
            int(has_ip_url),

        "has_shortened_url_pattern":
            int(has_shortened_url_pattern),

        "sender_domain_length":
            sender_domain_length,

        "subdomain_count":
            subdomain_count,

        "suspicious_attachment":
            int(suspicious_attachment),

        "generic_greeting":
            int(
                content_result[
                    "generic_greeting"
                ]
            ),

        "password_request":
            int(password_request),

        "personal_info_request":
            int(personal_info_request),

        "exclamation_count":
            count_exclamation_marks(
                f"{subject} {body}"
            ),

        "uppercase_ratio":
            calculate_uppercase_ratio(
                f"{subject} {body}"
            ),

        "body_length":
            len(body),

        "subject_length":
            len(subject),
    }

    return features

