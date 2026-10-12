import re


DANGEROUS_EXTENSIONS = [
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".js",
    ".vbs",
    ".ps1",
]


ARCHIVE_EXTENSIONS = [
    ".zip",
    ".rar",
    ".7z",
]


SAFE_DOCUMENT_EXTENSIONS = [
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".txt",
]


def analyze_attachment(filename):
    """
    Perform safe static analysis of an attachment filename.
    The file is NOT opened or executed.
    """

    if not filename:
        return {
            "attachment_risk_score": 0,
            "suspicious_attachment": False,
            "attachment_findings": [
                "No attachment provided."
            ]
        }

    filename = str(filename).strip().lower()

    risk_score = 0
    findings = []

    # -------------------------------------------------
    # Dangerous extension
    # -------------------------------------------------
    dangerous_extension = any(
        filename.endswith(extension)
        for extension in DANGEROUS_EXTENSIONS
    )

    if dangerous_extension:
        risk_score += 25
        findings.append(
            "Attachment uses an executable or script file extension."
        )

    # -------------------------------------------------
    # Archive extension
    # -------------------------------------------------
    archive_extension = any(
        filename.endswith(extension)
        for extension in ARCHIVE_EXTENSIONS
    )

    if archive_extension:
        risk_score += 10
        findings.append(
            "Attachment is an archive file that may contain "
            "other files."
        )

    # -------------------------------------------------
    # Double extension detection
    # -------------------------------------------------
    parts = filename.split(".")

    if len(parts) >= 3:
        first_extension = "." + parts[-2]
        final_extension = "." + parts[-1]

        if (
            first_extension in SAFE_DOCUMENT_EXTENSIONS
            and final_extension in DANGEROUS_EXTENSIONS
        ):
            risk_score += 25
            findings.append(
                "Attachment uses a suspicious double-extension "
                "pattern such as document.pdf.exe."
            )

    # -------------------------------------------------
    # Final score
    # -------------------------------------------------
    risk_score = min(risk_score, 100)

    suspicious_attachment = risk_score > 0

    if not findings:
        findings.append(
            "No major attachment filename anomalies were detected."
        )

    return {
        "attachment_risk_score": risk_score,
        "suspicious_attachment": suspicious_attachment,
        "attachment_findings": findings,
    }