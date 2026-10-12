import random
import pandas as pd

random.seed(42)

# ---------------------------------------------------------
# Synthetic Phishing Email Dataset Generator
# Defensive / Educational Use Only
# ---------------------------------------------------------

LEGITIMATE_EMAILS = [
    {
        "sender": "training@example.org",
        "subject": "Cybersecurity Workshop Reminder",
        "body": (
            "Hello Team,\n\n"
            "This is a reminder about the cybersecurity workshop scheduled "
            "for tomorrow at 10 AM. Please join using the official meeting "
            "calendar invitation.\n\n"
            "Regards,\nTraining Team"
        ),
        "urls": "https://example.org/workshop",
        "attachment_name": "workshop_schedule.pdf",
    },
    {
        "sender": "hr@example.org",
        "subject": "Monthly Employee Newsletter",
        "body": (
            "Hello Everyone,\n\n"
            "Please find this month's employee newsletter attached. "
            "It contains updates about upcoming activities and events.\n\n"
            "Regards,\nHR Team"
        ),
        "urls": "https://example.org/newsletter",
        "attachment_name": "newsletter.pdf",
    },
    {
        "sender": "support@example.com",
        "subject": "Your Support Ticket Update",
        "body": (
            "Hello,\n\n"
            "Your support ticket has been updated. "
            "You can review the status through the official support portal.\n\n"
            "Regards,\nSupport Team"
        ),
        "urls": "https://example.com/support",
        "attachment_name": "",
    },
]

PHISHING_EMAILS = [
    {
        "sender": "security-alert@account-check.invalid.test",
        "subject": "URGENT: Your Account Will Be Suspended!",
        "body": (
            "URGENT! Your account will be suspended immediately. "
            "Verify your password and account information now to avoid "
            "permanent suspension. Click the link below immediately."
        ),
        "urls": "http://198.51.100.10/verify-account",
        "attachment_name": "",
    },
    {
        "sender": "payment-team@billing-alert.invalid.test",
        "subject": "Immediate Payment Required",
        "body": (
            "Your payment could not be processed. "
            "You must provide your payment information immediately "
            "to prevent your account from being closed."
        ),
        "urls": "http://payment-check.invalid.test/login",
        "attachment_name": "",
    },
    {
        "sender": "account-security@verify.invalid.test",
        "subject": "Password Verification Required",
        "body": (
            "Dear Customer,\n\n"
            "We detected unusual activity on your account. "
            "Please confirm your username and password immediately "
            "to secure your account."
        ),
        "urls": "http://verify.invalid.test/account/password",
        "attachment_name": "",
    },
    {
        "sender": "rewards@prize.invalid.test",
        "subject": "Congratulations! You Won a Prize",
        "body": (
            "Congratulations! You have been selected for an exclusive reward. "
            "Claim your prize immediately by providing your personal information."
        ),
        "urls": "http://reward.invalid.test/claim",
        "attachment_name": "",
    },
    {
        "sender": "invoice@finance-alert.invalid.test",
        "subject": "Final Notice: Invoice Payment",
        "body": (
            "FINAL NOTICE! Your invoice is overdue. "
            "Payment must be completed immediately or your account will be "
            "reported and suspended."
        ),
        "urls": "http://finance.invalid.test/payment",
        "attachment_name": "invoice.pdf.exe",
    },
]


def generate_legitimate_email(email_id):
    template = random.choice(LEGITIMATE_EMAILS)

    return {
        "email_id": email_id,
        "sender": template["sender"],
        "sender_domain": template["sender"].split("@")[-1],
        "subject": template["subject"],
        "body": template["body"],
        "urls": template["urls"],
        "attachment_name": template["attachment_name"],
        "label": "LEGITIMATE",
    }


def generate_phishing_email(email_id):
    template = random.choice(PHISHING_EMAILS)

    return {
        "email_id": email_id,
        "sender": template["sender"],
        "sender_domain": template["sender"].split("@")[-1],
        "subject": template["subject"],
        "body": template["body"],
        "urls": template["urls"],
        "attachment_name": template["attachment_name"],
        "label": "PHISHING",
    }


def generate_dataset(total_records=600):
    records = []

    # Balanced dataset
    legitimate_count = total_records // 2
    phishing_count = total_records - legitimate_count

    for i in range(legitimate_count):
        records.append(
            generate_legitimate_email(f"EMAIL-{i + 1:04d}")
        )

    for i in range(phishing_count):
        records.append(
            generate_phishing_email(
                f"EMAIL-{legitimate_count + i + 1:04d}"
            )
        )

    random.shuffle(records)

    return pd.DataFrame(records)


if __name__ == "__main__":
    dataset = generate_dataset(600)

    output_file = "data/phishing_email_dataset.csv"

    dataset.to_csv(output_file, index=False)

    print("=" * 60)
    print("Synthetic Phishing Email Dataset Generated")
    print("=" * 60)
    print(f"Total records : {len(dataset)}")
    print(f"Legitimate    : {(dataset['label'] == 'LEGITIMATE').sum()}")
    print(f"Phishing      : {(dataset['label'] == 'PHISHING').sum()}")
    print(f"Output file   : {output_file}")
    print("=" * 60)