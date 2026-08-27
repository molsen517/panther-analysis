"""
Insider Threat / Compromised Contractor — Stage 2 Detection
AWS CloudTrail: Bulk S3 GetObject — data staging

Panther schema: AWS.CloudTrail
Uses Threshold: 50 — fires after 50 GetObject events in 10-minute dedup window.

Fires on:
  - S3 GetObject events from any IAM principal
  - Threshold of 50 events in 10 minutes triggers the alert
  - Filters out known automated backup/sync principals
"""

from panther_base_helpers import deep_get

# IAM principals known to perform legitimate bulk S3 reads
# Expand with customer-specific service accounts
ALLOWED_BULK_PRINCIPALS = {
    "backup-service",
    "dr-sync-role",
    "analytics-etl",
    "cloudtrail-delivery",
    "aws-config-delivery",
}

# Buckets that legitimately receive high-volume reads
EXCLUDED_BUCKETS = {
    "aws-cloudtrail-logs",
    "aws-config-snapshots",
    "elasticmapreduce-logs",
}


def rule(event) -> bool:
    event_name = deep_get(event, "eventName", default="")
    if event_name != "GetObject":
        return False

    # Exclude known automated principals
    principal = deep_get(event, "userIdentity", "userName", default="")
    if not principal:
        principal = deep_get(event, "userIdentity", "sessionContext",
                             "sessionIssuer", "userName", default="")
    if any(allowed in principal.lower() for allowed in ALLOWED_BULK_PRINCIPALS):
        return False

    # Exclude known high-volume buckets
    bucket = deep_get(event, "requestParameters", "bucketName", default="")
    if bucket in EXCLUDED_BUCKETS:
        return False

    return True


def title(event) -> str:
    principal = deep_get(event, "userIdentity", "arn", default="unknown principal")
    bucket    = deep_get(event, "requestParameters", "bucketName", default="unknown bucket")
    src_ip    = deep_get(event, "sourceIPAddress", default="unknown IP")
    return f"[AWS] Bulk S3 download from {bucket} by {principal} from {src_ip}"


def alert_context(event) -> dict:
    uid = deep_get(event, "userIdentity", default={})
    return {
        "principal_arn":  uid.get("arn"),
        "principal_type": uid.get("type"),
        "username":       uid.get("userName"),
        "account_id":     uid.get("accountId"),
        "bucket":         deep_get(event, "requestParameters", "bucketName"),
        "object_key":     deep_get(event, "requestParameters", "key"),
        "source_ip":      deep_get(event, "sourceIPAddress"),
        "region":         deep_get(event, "awsRegion"),
        "event_time":     deep_get(event, "eventTime"),
        "user_agent":     deep_get(event, "userAgent"),
        "event_id":       deep_get(event, "eventID"),
        "mfa_used":       deep_get(event, "userIdentity", "sessionContext",
                                   "attributes", "mfaAuthenticated"),
    }


def dedup(event) -> str:
    principal = deep_get(event, "userIdentity", "arn", default="unknown")
    bucket    = deep_get(event, "requestParameters", "bucketName", default="unknown")
    return f"s3-bulk-download:{principal}:{bucket}"
