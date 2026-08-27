"""
Insider Threat / Compromised Contractor — Stage 1 Detection
Entra ID: Off-hours sign-in from unregistered device with no MFA

Panther schema: Azure.Audit (category: SignInLogs)
Fields nested under `properties` per Azure.Audit schema.

Fires on:
  - Sign-in between 22:00-06:00 UTC (off-hours)
  - AND (unregistered device OR MFA not satisfied OR high-risk country)
"""

from datetime import datetime, timezone
from panther_base_helpers import deep_get

# Off-hours window in UTC — 10pm to 6am
OFF_HOURS_START = 22
OFF_HOURS_END   = 6

# Countries that should never be signing in — add customer-specific list
HIGH_RISK_COUNTRIES = {
    "RO", "RU", "CN", "KP", "IR", "NG", "UA", "BY",
}

# Corporate IP prefixes — expand with customer ranges
CORPORATE_IP_PREFIXES = ("10.", "172.16.", "192.168.", "203.0.113.")


def _is_signin_event(event) -> bool:
    return deep_get(event, "category", default="") == "SignInLogs"


def _is_off_hours(event) -> bool:
    created = deep_get(event, "properties", "createdDateTime", default="")
    if not created:
        return False
    try:
        dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
        hour = dt.hour
        return hour >= OFF_HOURS_START or hour < OFF_HOURS_END
    except Exception:
        return False


def _is_unregistered_device(event) -> bool:
    device_id = deep_get(event, "properties", "deviceDetail", "deviceId", default="")
    return not device_id or device_id == ""


def _mfa_not_satisfied(event) -> bool:
    ca_status = deep_get(event, "properties", "conditionalAccessStatus", default="")
    auth_details = deep_get(event, "properties", "authenticationDetails", default=[])

    # Conditional access not applied or failed
    if ca_status not in ("success", "notApplied"):
        return True

    # No MFA method in authentication details
    mfa_methods = {
        "microsoft authenticator", "authenticator app", "sms", "phone call",
        "fido2 security key", "hardware oath token", "software oath token",
        "windows hello for business",
    }
    methods_used = {
        d.get("authenticationMethod", "").lower()
        for d in auth_details
        if d.get("succeeded")
    }
    return not any(m in methods_used for m in mfa_methods)


def _is_high_risk_country(event) -> bool:
    country = deep_get(event, "properties", "location", "countryOrRegion", default="")
    return country.upper() in HIGH_RISK_COUNTRIES


def _is_external_ip(event) -> bool:
    ip = deep_get(event, "properties", "ipAddress", default="")
    return not any(ip.startswith(prefix) for prefix in CORPORATE_IP_PREFIXES)


def rule(event) -> bool:
    if not _is_signin_event(event):
        return False

    # Must be successful sign-in
    error_code = deep_get(event, "properties", "status", "errorCode", default=-1)
    if error_code != 0:
        return False

    # Must be off-hours
    if not _is_off_hours(event):
        return False

    # Must have at least one risk indicator
    return (
        _is_unregistered_device(event) or
        _mfa_not_satisfied(event) or
        _is_high_risk_country(event) or
        _is_external_ip(event)
    )


def title(event) -> str:
    upn     = deep_get(event, "properties", "userPrincipalName", default="unknown user")
    ip      = deep_get(event, "properties", "ipAddress", default="unknown IP")
    country = deep_get(event, "properties", "location", "countryOrRegion", default="unknown")
    time    = deep_get(event, "properties", "createdDateTime", default="")

    risk_flags = []
    if _is_unregistered_device(event):
        risk_flags.append("unregistered device")
    if _mfa_not_satisfied(event):
        risk_flags.append("no MFA")
    if _is_high_risk_country(event):
        risk_flags.append(f"high-risk country ({country})")
    if _is_external_ip(event):
        risk_flags.append("external IP")

    flags = " + ".join(risk_flags) if risk_flags else "anomalous"
    return f"[Entra] Off-hours login: {upn} from {ip} ({country}) — {flags}"


def alert_context(event) -> dict:
    return {
        "upn":            deep_get(event, "properties", "userPrincipalName"),
        "ip_address":     deep_get(event, "properties", "ipAddress"),
        "country":        deep_get(event, "properties", "location", "countryOrRegion"),
        "city":           deep_get(event, "properties", "location", "city"),
        "device_id":      deep_get(event, "properties", "deviceDetail", "deviceId"),
        "device_name":    deep_get(event, "properties", "deviceDetail", "displayName"),
        "os":             deep_get(event, "properties", "deviceDetail", "operatingSystem"),
        "ca_status":      deep_get(event, "properties", "conditionalAccessStatus"),
        "risk_level":     deep_get(event, "properties", "riskLevelAggregated"),
        "sign_in_time":   deep_get(event, "properties", "createdDateTime"),
        "unregistered":   _is_unregistered_device(event),
        "no_mfa":         _mfa_not_satisfied(event),
        "high_risk_country": _is_high_risk_country(event),
        "external_ip":    _is_external_ip(event),
        "correlation_id": deep_get(event, "correlationId"),
    }


def dedup(event) -> str:
    upn = deep_get(event, "properties", "userPrincipalName", default="unknown")
    return f"offhours-login:{upn}"
