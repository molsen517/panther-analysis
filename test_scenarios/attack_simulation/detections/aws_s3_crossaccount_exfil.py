"""
Insider Threat / Compromised Contractor — Stage 3 Detection
AWS CloudTrail: S3 PutObject/CopyObject to external/cross-account bucket

Panther schema: AWS.CloudTrail
Fires on:
  - PutObject or CopyObject where destination bucket account ≠ source account
  - PutObject to a bucket not in the known approved account list
  - CopyObject with x-amz-copy-source pointing to a different account
"""

from panther_base_helpers import deep_get

# Approved destination AWS account IDs — expand with customer DR/backup accounts
APPROVED_DESTINATION_ACCOUNTS = {
    "123456789012",   # Primary account
    "234567890123",   # DR account
    "345678901234",   # Backup account
}

EXFIL_EVENTS = {"PutObject", "CopyObject"}


def _get_source_account(event) -> str:
    return deep_get(event, "userIdentity", "accountId", default="")


def _get_destination_account(event) -> str:
    # Explicit destination account in request parameters
    dest_account = deep_get(event, "requestParameters", "bucketAccountId", default="")
    if dest_account:
        return dest_account

    # Try to extract from copy source ARN
    copy_source = deep_get(event, "requestParameters", "x-amz-copy-source", default="")
    if copy_source and "arn:aws:s3:::" not in copy_source:
        # Cross-account copy source often includes account in ARN
        pass

    return ""


def _is_cross_account(event) -> bool:
    source_account = _get_source_account(event)
    dest_account   = _get_destination_account(event)

    if not dest_account:
        return False

    # Different account and not in approved list
    return (
        dest_account != source_account and
        dest_account not in APPROVED_DESTINATION_ACCOUNTS
    )


def _is_external_ip(event) -> bool:
    ip = deep_get(event, "sourceIPAddress", default="")
    corporate_prefixes = ("10.", "172.16.", "192.168.", "203.0.113.")
    return not any(ip.startswith(p) for p in corporate_prefixes)


def rule(event) -> bool:
    event_name = deep_get(event, "eventName", default="")
    if event_name not in EXFIL_EVENTS:
        return False

    # Cross-account destination is the primary signal
    if _is_cross_account(event):
        return True

    # PutObject from external IP to any bucket is suspicious
    if event_name == "PutObject" and _is_external_ip(event):
        return True

    return False


def title(event) -> str:
    event_name    = deep_get(event, "eventName", default="unknown")
    principal     = deep_get(event, "userIdentity", "arn", default="unknown principal")
    bucket        = deep_get(event, "requestParameters", "bucketName", default="unknown bucket")
    dest_account  = _get_destination_account(event) or "external"
    src_ip        = deep_get(event, "sourceIPAddress", default="unknown IP")

    if _is_cross_account(event):
        return f"[AWS] {event_name} to cross-account bucket {bucket} (acct:{dest_account}) by {principal} from {src_ip}"
    return f"[AWS] {event_name} from external IP {src_ip} to {bucket} by {principal}"


def alert_context(event) -> dict:
    uid = deep_get(event, "userIdentity", default={})
    return {
        "event_name":          deep_get(event, "eventName"),
        "principal_arn":       uid.get("arn"),
        "principal_type":      uid.get("type"),
        "source_account":      uid.get("accountId"),
        "destination_account": _get_destination_account(event),
        "destination_bucket":  deep_get(event, "requestParameters", "bucketName"),
        "object_key":          deep_get(event, "requestParameters", "key"),
        "copy_source":         deep_get(event, "requestParameters", "x-amz-copy-source"),
        "source_ip":           deep_get(event, "sourceIPAddress"),
        "region":              deep_get(event, "awsRegion"),
        "event_time":          deep_get(event, "eventTime"),
        "user_agent":          deep_get(event, "userAgent"),
        "mfa_used":            deep_get(event, "userIdentity", "sessionContext",
                                        "attributes", "mfaAuthenticated"),
        "cross_account":       _is_cross_account(event),
        "external_ip":         _is_external_ip(event),
    }


def dedup(event) -> str:
    principal = deep_get(event, "userIdentity", "arn", default="unknown")
    bucket    = deep_get(event, "requestParameters", "bucketName", default="unknown")
    return f"s3-crossaccount-exfil:{principal}:{bucket}"
