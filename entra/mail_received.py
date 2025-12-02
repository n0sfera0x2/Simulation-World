#!/usr/bin/env python3
import argparse
import json
import uuid
import hashlib
from datetime import datetime, timedelta, timezone
from entra_simulator import EntraLogSimulator

EXCHANGE_ONLINE_APP_ID = "029f5f70-1642-2096-26f6-00cc4012391f"
EXCHANGE_ONLINE_APP_NAME = "Exchange Online"

def iso_utc_now_minus(hours: int) -> str:
    ts = datetime.now(timezone.utc) - timedelta(hours=hours)
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")

def safe_hashes(seed: str):
    md5 = hashlib.md5(seed.encode("utf-8")).hexdigest()
    sha256 = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    return md5, sha256

def build_email_block(
    recipient: str,
    sender: str,
    subject: str,
    url: str,
    delivery_time_iso: str,
    origination_time_iso: str,
    include_attachment: bool = True,
    attach_name: str = "Review_Security_Alert.html",
    attach_mime: str = "text/html",
    attach_size: int = 4821,
    return_path: str = "<bounce@contoso.com>",
) -> dict:
    message_id = f"<{uuid.uuid4()}@security.microsoft.com>"
    data_body = (
        f"Heads up! We detected an unusual sign-in attempt.\n\n"
        f"Review: {url}\n"
    )
    mime_header = 'multipart/alternative; boundary="----=_Part_12345_67890.1693673950"'

    email_block = {
        "Sender": sender,
        "Recipients": [recipient],
        "CC": [],
        "BCC": [],
        "Subject": subject,
        "Data": data_body,
        "Mime": mime_header,
        "ReturnPath": return_path,
        "MessageId": message_id,
        "DeliveryTime": delivery_time_iso,
        "OriginationTime": origination_time_iso,
    }

    if include_attachment:
        # Derive a simple (deterministic) pair of hashes from subject+url+filename for demos
        md5, sha256 = safe_hashes(subject + url + attach_name)

        # Build a plausible local path for the recipient's mailbox client cache
        directory = f"/Users/{recipient.split('@')[0]}/Library/Mail/Attachments/"
        path = directory + attach_name
        extension = attach_name.split(".")[-1] if "." in attach_name else ""

        email_block["Attachment"] = {
            "filename": attach_name,
            "path": path,
            "directory": directory,
            "extension": extension,
            "file_type": attach_mime,
            "md5": md5,
            "sha256": sha256,
            "is_signed": False,
            "signer": "",
            "signature_status": "UNSIGNED",
            "size": int(attach_size),
        }

    return email_block

def main():
    parser = argparse.ArgumentParser(description="Inject phishing email delivery log (o365_exchange_raw).")
    parser.add_argument("--username", required=True, help="User email to receive the phishing email")
    parser.add_argument("--output", required=True, help="Output path for the JSONL log file")
    parser.add_argument("--hours-ago", type=int, default=2, help="How many hours ago the email was received")

    # Optional knobs for the attachment/body if you want to vary the demo
    parser.add_argument("--no-attachment", action="store_true", help="Do not include an attachment block")
    parser.add_argument("--attach-name", default="Review_Security_Alert.html", help="Attachment filename")
    parser.add_argument("--attach-mime", default="text/html", help="Attachment MIME type")
    parser.add_argument("--attach-size", type=int, default=4821, help="Attachment size in bytes")

    # Optional content tweaks
    parser.add_argument("--sender", default="alerts@security.microsoft.com", help="From address")
    parser.add_argument("--subject", default="🔐 Unusual Sign-in Attempt Detected - Review Immediately", help="Email subject")
    parser.add_argument("--url", default="https://login.microsoftonline.com-reset-verify.com/session", help="Suspicious URL inside the message")

    args = parser.parse_args()

    iso_timestamp = iso_utc_now_minus(args.hours_ago)

    # Initialize simulator
    simulator = EntraLogSimulator(
        users_file="/home/spen/entra_logs/configs/users.yaml",
        service_principals_file="/home/spen/entra_logs/configs/service_principals.yaml",
        template_file="/home/spen/entra_logs/templates/entra_template.json",
        org_config_file="/home/spen/entra_logs/configs/org_config.yaml",
        apps_file="/home/spen/entra_logs/configs/apps.yaml",
        operations_file="/home/spen/entra_logs/configs/operations.yaml",
        output_file=args.output
    )

    # Get user
    user = next((u for u in simulator.users if u["user_id"] == args.username), None)
    if not user:
        raise ValueError(f"User '{args.username}' not found in users.yaml")

    # Compose the content we want to inject into the template
    # (We still let the simulator render core/existing fields, then enrich.)
    user_for_render = user.copy()
    user_for_render.update({
        "email_sender": args.sender,
        "email_subject": args.subject,
        "email_url": args.url
    })

    # Locate the MailReceived operation
    mail_op = next((op for op in simulator.operations if op["name"] == "MailReceived"), None)
    if not mail_op:
        raise ValueError("Operation 'MailReceived' not found in operations.yaml")

    # Render base record from the template
    log = simulator._render_template(
        entity=user_for_render,
        operation=mail_op,
        timestamp=iso_timestamp,
        is_failure=False,
        is_spn=False
    )

    # ── Ensure/override fields to match the enhanced o365_exchange_raw shape ──
    # Core “MailReceived” semantics
    log["_time"] = iso_timestamp
    log["Operation"] = "MailReceived"

    # Normalize event outcome fields commonly used in your mapper
    # (ResultStatus, ResultType, RecordType should already be present from template; keep if set)
    log.setdefault("ResultStatus", "Success")
    log.setdefault("ResultType", "0")
    log.setdefault("RecordType", "15")

    # Workload/App context (force Exchange for this record)
    log["AppId"] = EXCHANGE_ONLINE_APP_ID
    log["AppDisplayName"] = EXCHANGE_ONLINE_APP_NAME
    log["Workload"] = "AzureActiveDirectory" if log.get("Workload") is None else log["Workload"]

    # Place suspicious URL at the top level for xdm.network.http.url mapping convenience
    log["MaliciousLink"] = args.url

    # Resource hint for mapper (mailbox activity)
    log["Resource"] = "Mailbox"

    # Email block (rich XDM-aligned structure)
    email_block = build_email_block(
        recipient=args.username,
        sender=args.sender,
        subject=args.subject,
        url=args.url,
        delivery_time_iso=iso_timestamp,
        origination_time_iso=iso_timestamp,  # or (hours_ago + small offset) if you want variance
        include_attachment=(not args.no_attachment),
        attach_name=args.attach_name,
        attach_mime=args.attach_mime,
        attach_size=args.attach_size,
    )
    log["Email"] = email_block

    # Sensible defaults if template didn’t provide these (kept generic; tweak as you like)
    log.setdefault("DeviceDetail", {"DeviceId": "device-099", "OperatingSystem": "macOS", "Browser": "Safari"})
    log.setdefault("UserAgent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")
    log.setdefault("GeoLocation", {"Country": "US", "City": "New York"})
    log.setdefault("ASN", {"ASN": "AS7018", "ASN_Name": "ATT-INTERNET4", "IsProxy": "false"})
    log.setdefault("AdditionalDetails", [
        {"Key": "AuthenticationRequirement", "Value": "None"},
        {"Key": "MfaRequired", "Value": "false"}
    ])

    # Write JSONL
    with open(args.output, "w") as f:
        f.write(json.dumps(log) + "\n")

    print(f"[+] Phishing mail log injected for {args.username} at {iso_timestamp}")

if __name__ == "__main__":
    main()
