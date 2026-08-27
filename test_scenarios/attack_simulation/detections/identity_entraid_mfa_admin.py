"""
Identity: Entra ID — MFA Reset or Admin Role Assignment
Azure.Audit (AuditLogs category)

Detects:
  - MFA methods reset/cleared on user accounts
  - Users added to Global Administrator or equivalent privileged roles

ATT&CK: T1098.005, T1078.004
"""

from panther_base_helpers import deep_get

PRIVILEGED_ROLES = {
    "global administrator",
    "privileged role administrator",
    "security administrator",
    "user administrator",
    "application administrator",
    "cloud application administrator",
    "exchange administrator",
}


def _is_audit(event) -> bool:
    return deep_get(event, "category", default="") == "AuditLogs"


def _mfa_reset(event) -> bool:
    """True if StrongAuthenticationMethods was cleared to empty."""
    targets = deep_get(event, "properties", "targetResources", default=[])
    for t in targets:
        for prop in t.get("modifiedProperties", []):
            if prop.get("displayName") == "StrongAuthenticationMethods":
                new_val = prop.get("newValue", "")
                if new_val in ("[]", "", "null"):
                    return True
    return False


def _admin_role_added(event) -> bool:
    """True if a privileged role was assigned."""
    op = deep_get(event, "operationName", default="").lower()
    if "add member to role" not in op:
        return False
    targets = deep_get(event, "properties", "targetResources", default=[])
    for t in targets:
        if t.get("type") == "Role":
            role_name = (t.get("displayName") or "").lower()
            if any(r in role_name for r in PRIVILEGED_ROLES):
                return True
    return False


def rule(event) -> bool:
    if not _is_audit(event):
        return False
    return _mfa_reset(event) or _admin_role_added(event)


def title(event) -> str:
    actor = deep_get(event, "properties", "initiatedBy", "user",
                     "userPrincipalName") or "unknown"
    ip    = deep_get(event, "callerIpAddress") or "unknown IP"
    op    = deep_get(event, "operationName") or ""

    targets = deep_get(event, "properties", "targetResources", default=[])
    target_upn = next(
        (t.get("userPrincipalName") for t in targets if t.get("type") == "User"),
        "unknown"
    )
    role = next(
        (t.get("displayName") for t in targets if t.get("type") == "Role"),
        None
    )

    if role:
        return f"[Identity] Admin role assigned: {role} → {target_upn} by {actor} from {ip}"
    return f"[Identity] MFA reset: {target_upn} by {actor} from {ip}"


def alert_context(event) -> dict:
    targets = deep_get(event, "properties", "targetResources", default=[])
    return {
        "actor":        deep_get(event, "properties", "initiatedBy", "user", "userPrincipalName"),
        "actor_ip":     deep_get(event, "callerIpAddress"),
        "operation":    deep_get(event, "operationName"),
        "target_users": [t.get("userPrincipalName") for t in targets if t.get("type") == "User"],
        "role_assigned":[t.get("displayName") for t in targets if t.get("type") == "Role"],
        "mfa_reset":    _mfa_reset(event),
        "admin_role":   _admin_role_added(event),
    }


def dedup(event) -> str:
    actor = deep_get(event, "properties", "initiatedBy", "user",
                     "userPrincipalName") or "unknown"
    op    = deep_get(event, "operationName") or "unknown"
    return f"{actor}:{op}"
