"""
Cloud: AWS Backup Destruction
AWS.CloudTrail

Detects:
  - EC2 snapshot deletion
  - S3 versioning suspended or disabled
  - RDS automated backup disabled

ATT&CK: T1490 — Inhibit System Recovery
"""

from panther_base_helpers import deep_get

DESTRUCTION_EVENTS = {
    "DeleteSnapshot",
    "DeleteBackup",
    "DeleteDBSnapshot",
    "DeleteDBClusterSnapshot",
}

VERSIONING_SUSPEND_EVENTS = {"PutBucketVersioning"}


def _snapshot_deleted(event) -> bool:
    return event.get("eventName") in DESTRUCTION_EVENTS


def _versioning_disabled(event) -> bool:
    if event.get("eventName") not in VERSIONING_SUSPEND_EVENTS:
        return False
    status = deep_get(event, "requestParameters",
                      "VersioningConfiguration", "Status", default="")
    return status in ("Suspended", "Disabled", "Off")


def rule(event) -> bool:
    return _snapshot_deleted(event) or _versioning_disabled(event)


def title(event) -> str:
    event_name = event.get("eventName") or "unknown"
    principal  = deep_get(event, "userIdentity", "arn") or "unknown"
    src_ip     = event.get("sourceIPAddress") or "unknown IP"
    region     = event.get("awsRegion") or ""

    if _versioning_disabled(event):
        bucket = deep_get(event, "requestParameters", "bucketName") or "unknown bucket"
        return f"[Cloud] S3 versioning disabled: {bucket} by {principal} from {src_ip}"
    resource = (deep_get(event, "requestParameters", "snapshotId") or
                deep_get(event, "requestParameters", "backupVaultName") or "unknown")
    return f"[Cloud] Backup destroyed: {event_name} {resource} by {principal} [{region}]"


def alert_context(event) -> dict:
    uid = deep_get(event, "userIdentity", default={})
    return {
        "event_name":    event.get("eventName"),
        "principal_arn": uid.get("arn"),
        "account_id":    uid.get("accountId"),
        "source_ip":     event.get("sourceIPAddress"),
        "region":        event.get("awsRegion"),
        "snapshot_id":   deep_get(event, "requestParameters", "snapshotId"),
        "bucket":        deep_get(event, "requestParameters", "bucketName"),
        "versioning":    deep_get(event, "requestParameters", "VersioningConfiguration"),
        "mfa_used":      deep_get(event, "userIdentity", "sessionContext",
                                  "attributes", "mfaAuthenticated"),
    }


def dedup(event) -> str:
    principal = deep_get(event, "userIdentity", "arn") or "unknown"
    return f"backup-destruction:{principal}"
