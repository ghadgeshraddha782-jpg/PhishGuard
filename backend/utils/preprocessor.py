import re


def clean_text(text):
    """
    Clean email text while preserving useful
    security-related information.
    """

    if text is None:
        return ""

    text = str(text)

    # Normalize whitespace
    text = re.sub(r"\s+", " ", text)

    # Remove leading/trailing spaces
    text = text.strip()

    return text


def extract_urls(text):
    """
    Extract URLs from email text.
    """

    if not text:
        return []

    url_pattern = r"https?://[^\s]+"

    urls = re.findall(url_pattern, text)

    return urls


def extract_sender_domain(sender):
    """
    Extract domain from sender email address.
    """

    if not sender or "@" not in sender:
        return ""

    return sender.split("@")[-1].lower().strip()


def extract_attachment_extension(filename):
    """
    Extract attachment extension.
    """

    if not filename:
        return ""

    filename = str(filename).lower().strip()

    if "." not in filename:
        return ""

    return filename.split(".")[-1]


def calculate_uppercase_ratio(text):
    """
    Calculate the ratio of uppercase characters
    in the given text.
    """

    if not text:
        return 0.0

    letters = [char for char in text if char.isalpha()]

    if not letters:
        return 0.0

    uppercase_letters = [
        char for char in letters if char.isupper()
    ]

    return len(uppercase_letters) / len(letters)


def count_exclamation_marks(text):
    """
    Count exclamation marks in text.
    """

    if not text:
        return 0

    return text.count("!")


def count_keyword_occurrences(text, keywords):
    """
    Count occurrences of security-related keywords.
    """

    if not text:
        return 0

    text = text.lower()

    count = 0

    for keyword in keywords:
        count += text.count(keyword.lower())

    return count