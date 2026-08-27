#!/usr/bin/env python3
"""
EDR UDM Test Event Sender
Reads sample events from edr_test_events.yml and sends them to
Panther HTTP log sources for detection testing.

Usage:
    python send_edr_events.py                        # send all events
    python send_edr_events.py --malicious-only       # only events that should trigger detections
    python send_edr_events.py --benign-only          # only benign/baseline events
    python send_edr_events.py --vendor sentinelone   # filter by vendor
    python send_edr_events.py --detection EDR.UDM.Credential.Dumping.Tool
    python send_edr_events.py --dry-run              # print events without sending
    python send_edr_events.py --killchain            # send full 3-stage kill chain with stage delays
"""

import argparse
import json
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import urllib.request
import urllib.error
import yaml

# ─────────────────────────────────────────────
#  CONFIG — loaded dynamically from tenants.yml
#  Use --tenant flag to select target environment
# ─────────────────────────────────────────────
TENANTS_FILE = Path(__file__).parent / "tenants.yml"

def load_tenant_config(tenant_name: str) -> dict:
    """Load log source config for the specified tenant from tenants.yml."""
    if not TENANTS_FILE.exists():
        print(f"❌ tenants.yml not found at {TENANTS_FILE}")
        sys.exit(1)
    with open(TENANTS_FILE) as f:
        all_tenants = yaml.safe_load(f)
    if tenant_name not in all_tenants:
        available = ", ".join(all_tenants.keys())
        print(f"❌ Tenant '{tenant_name}' not found in tenants.yml")
        print(f"   Available tenants: {available}")
        sys.exit(1)
    return all_tenants[tenant_name].get("log_sources", {})

# Global CONFIG — populated after --tenant arg is parsed
CONFIG = {}

LOG_TYPE_VENDOR_MAP = {
    "Crowdstrike":           "crowdstrike",
    "SentinelOne":           "sentinelone",
    "CarbonBlack":           "carbonblack",
    "MicrosoftDefenderXDR":  "defender",
    "Azure":                 "azure_audit",
    "AWS":                   "aws_cloudtrail",
    "Okta":                  "okta",
    "Auth0":                 "auth0",
    "GSuite":                "gsuite",
    "OnePassword":           "onepassword",   # ← 1Password audit events
}

EVENTS_FILE = Path(__file__).parent / "edr_test_events.yml"
DELAY_BETWEEN_EVENTS = 0.3    # seconds between individual events
KILLCHAIN_STAGE_DELAY = 480.0  # 8 minutes between stages


# ─────────────────────────────────────────────
#  Core send function
# ─────────────────────────────────────────────

def send_event(event_data: dict, vendor: str, dry_run: bool = False) -> bool:
    cfg = CONFIG.get(vendor)
    if not cfg:
        print(f"  ⚠️  No config found for vendor '{vendor}' — skipping")
        return False

    if dry_run:
        print(f"  [DRY RUN] Would POST to {cfg['url'][:60]}...")
        print(f"  Payload: {json.dumps(event_data, indent=2)[:300]}...")
        return True

    payload = json.dumps(event_data).encode("utf-8")
    req = urllib.request.Request(
        cfg["url"],
        data=payload,
        headers={
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {cfg['token']}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status in (200, 202)
    except urllib.error.HTTPError as e:
        print(f"  ❌ HTTP {e.code}: {e.reason}")
        return False
    except urllib.error.URLError as e:
        print(f"  ❌ Connection error: {e.reason}")
        return False


# ─────────────────────────────────────────────
#  Load + filter events
# ─────────────────────────────────────────────

def load_events(path: Path) -> list[dict]:
    with open(path) as f:
        data = yaml.safe_load(f)
    return data.get("events", [])


def get_vendor(log_type: str) -> str:
    for prefix, vendor in LOG_TYPE_VENDOR_MAP.items():
        if log_type.startswith(prefix):
            return vendor
    return "unknown"


def filter_events(events: list[dict], args) -> list[dict]:
    filtered = events

    if args.malicious_only:
        filtered = [e for e in filtered if e.get("malicious")]
    elif args.benign_only:
        filtered = [e for e in filtered if not e.get("malicious")]

    if args.vendor:
        filtered = [
            e for e in filtered
            if get_vendor(e["event"].get("p_log_type", "")) == args.vendor.lower()
        ]

    if args.scenario:
        filtered = [e for e in filtered if e.get("scenario") == args.scenario]

    if args.detection:
        filtered = [e for e in filtered if e.get("expected_detection") == args.detection]

    return filtered


# ─────────────────────────────────────────────
#  Payload preparation per vendor schema
# ─────────────────────────────────────────────

def prepare_payload(raw: dict, log_type: str, now_iso: str) -> dict:
    now_ms  = int(datetime.now(timezone.utc).timestamp() * 1000)
    now_sec = int(datetime.now(timezone.utc).timestamp())

    # ── SentinelOne.DeepVisibilityV2 ─────────────────────────────────────
    if log_type.startswith("SentinelOne"):
        raw.setdefault("account.id", "company-s1-account-01")
        et = raw.get("event.time")
        if et is None or et == 0:
            raw["event.time"] = now_ms
        elif isinstance(et, str):
            try:
                parsed = datetime.fromisoformat(et.replace("Z", "+00:00"))
                raw["event.time"] = int(parsed.timestamp() * 1000)
            except Exception:
                raw["event.time"] = now_ms
        return raw

    # ── OnePassword.AuditEvent ────────────────────────────────────────────
    # timestamp: 0 in the YAML triggers injection of current time (rfc3339)
    # uuid is required — generate one if missing
    # client.ip_address is the correlation field linking to S1 and CloudTrail
    if log_type.startswith("OnePassword"):
        if not raw.get("uuid"):
            raw["uuid"] = str(uuid.uuid4())
        ts = raw.get("timestamp")
        if ts is None or ts == 0:
            raw["timestamp"] = now_iso
        # Ensure session login_time is also current if set to 0
        session = raw.get("session", {})
        if isinstance(session, dict) and session.get("login_time") == 0:
            session["login_time"] = now_iso
            raw["session"] = session
        return raw

    # ── Azure.Audit (Entra ID) ────────────────────────────────────────────
    if log_type.startswith("Azure"):
        raw.setdefault("operationName", "Unknown Operation")
        raw.setdefault("category",      "AuditLogs")
        raw.setdefault("Level",         "Informational")
        raw.setdefault("correlationId", f"company-corr-{now_sec}")
        props = raw.setdefault("properties", {})
        props["activityDateTime"] = now_iso
        props.setdefault("result", "success")
        props.setdefault("initiatedBy", {
            "user": {
                "userPrincipalName": "unknown@corp.company.com",
                "ipAddress":         "0.0.0.0",
                "id":                "unknown-id",
            }
        })
        props.setdefault("targetResources", [])
        return raw

    # ── Okta.SystemLog ───────────────────────────────────────────────────
    if log_type.startswith("Okta"):
        raw.setdefault("version",  "0")
        raw.setdefault("severity", "INFO")
        raw.setdefault("displayMessage", raw.get("eventType", "Okta event"))
        pub = raw.get("published", "")
        if not pub or "2026-05-22" in pub or "2026-05-21" in pub:
            raw["published"] = now_iso
        return raw

    # ── Auth0.Events ─────────────────────────────────────────────────────
    if log_type.startswith("Auth0"):
        data = raw.setdefault("data", {})
        data["date"] = now_iso
        return raw

    # ── GSuite.ActivityEvent ──────────────────────────────────────────────
    if log_type.startswith("GSuite"):
        raw["kind"] = "admin#reports#activity"
        evt_id = raw.setdefault("id", {})
        evt_id["time"] = now_iso
        evt_id.setdefault("uniqueQualifier", str(now_sec))
        app = raw.pop("type", raw.get("name", "login"))
        evt_id.setdefault("applicationName", app)
        raw.setdefault("actor", {})
        evt_name   = raw.pop("name", "")
        evt_type   = raw.pop("type", "login")
        evt_params = raw.pop("parameters", {})
        params_list = [{"name": k, "value": v} for k, v in evt_params.items()] \
                      if isinstance(evt_params, dict) else evt_params
        raw["events"] = [{
            "type":       evt_type,
            "name":       evt_name,
            "parameters": params_list,
        }]
        return raw

    # ── AWS.CloudTrail ────────────────────────────────────────────────────
    if log_type.startswith("AWS"):
        raw.setdefault("eventVersion",       "1.08")
        raw.setdefault("eventType",          "AwsApiCall")
        raw.setdefault("awsRegion",          "us-east-1")
        raw.setdefault("eventID",            str(uuid.uuid4()))
        raw.setdefault("requestID",          str(uuid.uuid4()))
        raw.setdefault("recipientAccountId", "123456789012")
        raw["eventTime"] = now_iso
        raw.setdefault("userIdentity", {
            "type":      "AssumedRole",
            "arn":       "arn:aws:sts::123456789012:assumed-role/EngineeringAdmin/session-1",
            "accountId": "123456789012",
            "sessionContext": {
                "attributes": {
                    "mfaAuthenticated": "false",
                    "creationDate":     now_iso,
                },
                "sessionIssuer": {
                    "type":     "Role",
                    "arn":      "arn:aws:iam::123456789012:role/EngineeringAdmin",
                    "userName": "EngineeringAdmin",
                },
            },
        })
        return raw

    # ── CarbonBlack.EndpointEvent ─────────────────────────────────────────
    if log_type.startswith("CarbonBlack"):
        cb_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.000000 +0000 UTC")
        raw.setdefault("action",    "ACTION_CREATE_PROCESS")
        raw.setdefault("org_key",   "COMPANY-CB-ORG")
        raw.setdefault("device_id", "7245001")
        raw.setdefault("device_os", "WINDOWS")
        raw.setdefault("schema",    1)
        dt = raw.get("device_timestamp", "")
        if not dt or (isinstance(dt, str) and "T" in dt):
            try:
                parsed = datetime.fromisoformat(dt.replace("Z", "+00:00")) if dt else None
                raw["device_timestamp"] = (
                    parsed.strftime("%Y-%m-%d %H:%M:%S.000000 +0000 UTC") if parsed else cb_ts
                )
            except Exception:
                raw["device_timestamp"] = cb_ts
        else:
            raw.setdefault("device_timestamp", cb_ts)
        return raw

    # ── MicrosoftDefenderXDR.AdvancedHunting ─────────────────────────────
    if log_type.startswith("MicrosoftDefenderXDR"):
        if "properties" in raw:
            raw.setdefault("time",     now_iso)
            raw.setdefault("tenantId", "company-tenant-001")
            raw.setdefault("category", "AdvancedHunting-DeviceProcessEvents")
            return raw
        top_level  = {"time", "tenantId", "category"}
        properties = {k: v for k, v in raw.items() if k not in top_level}
        payload    = {k: v for k, v in raw.items() if k in top_level}
        payload.setdefault("time",     now_iso)
        payload.setdefault("tenantId", "company-tenant-001")
        payload.setdefault("category", "AdvancedHunting-DeviceProcessEvents")
        payload["properties"] = properties
        return payload

    # ── Crowdstrike.EventStreams ───────────────────────────────────────────
    if log_type.startswith("Crowdstrike"):
        if "metadata" in raw and "event" in raw:
            raw["metadata"].setdefault("eventCreationTime", now_ms)
            raw["event"].setdefault("UTCTimestamp", now_sec)
            return raw
        skip       = {"metadata", "event"}
        event_data = {k: v for k, v in raw.items() if k not in skip}
        return {
            "metadata": {
                "customerIDString":  "COMPANY-CS-CID-001",
                "eventType":         "DetectionSummaryEvent",
                "eventCreationTime": now_ms,
                "version":           "1.0",
                "offset":            1,
            },
            "event": event_data,
        }

    return raw


# ─────────────────────────────────────────────
#  Kill chain sender
# ─────────────────────────────────────────────

def send_killchain(events: list[dict], dry_run: bool, delay: float) -> tuple[int, int]:
    stages = {
        "killchain_stage_1": [],
        "killchain_stage_2": [],
        "killchain_stage_3": [],
    }
    untagged = []

    for e in events:
        scenario = e.get("scenario", "")
        if scenario in stages:
            stages[scenario].append(e)
        else:
            untagged.append(e)

    if all(len(v) == 0 for v in stages.values()):
        return send_batch(untagged, dry_run, delay)

    ok_total, fail_total = 0, 0
    stage_labels = {
        "killchain_stage_1": "Stage 1 — SentinelOne  LOLBin / Credential Dump",
        "killchain_stage_2": "Stage 2 — 1Password    Vault Access / Secret Harvest",
        "killchain_stage_3": "Stage 3 — AWS          Backup Destruction / Ransomware Prep",
    }

    for stage_key, label in stage_labels.items():
        batch = stages[stage_key]
        if not batch:
            continue
        print(f"\n{'─'*60}")
        print(f"  {label}")
        print(f"{'─'*60}")
        ok, fail = send_batch(batch, dry_run, delay)
        ok_total   += ok
        fail_total += fail
        if stage_key != "killchain_stage_3":
            print(f"\n  ⏳ Waiting {int(KILLCHAIN_STAGE_DELAY)}s ({int(KILLCHAIN_STAGE_DELAY/60)} min) before next stage...")
            if not dry_run:
                time.sleep(KILLCHAIN_STAGE_DELAY)

    return ok_total, fail_total


def send_batch(events: list[dict], dry_run: bool, delay: float) -> tuple[int, int]:
    ok, fail = 0, 0
    now_iso  = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    for i, entry in enumerate(events, 1):
        log_type  = entry["event"].get("p_log_type", "Unknown")
        vendor    = get_vendor(log_type)
        detection = entry.get("expected_detection", "—")
        label     = "🔴 MALICIOUS" if entry.get("malicious") else "🟢 BENIGN   "
        desc      = entry.get("description", "")

        print(f"[{i:02}/{len(events)}] {label}  {log_type:<45}  {desc}")
        if entry.get("malicious"):
            print(f"         Expected detection : {detection}")

        raw = entry["event"].copy()
        raw.pop("p_log_type", None)
        event_payload = prepare_payload(raw, log_type, now_iso)

        sent_ok = send_event(event_payload, vendor, dry_run=dry_run)
        if sent_ok:
            ok += 1
            if not dry_run:
                print(f"         ✅ Sent")
        else:
            fail += 1

        if i < len(events):
            time.sleep(delay)

    return ok, fail


# ─────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Send EDR + identity + cloud test events to Panther")
    parser.add_argument("--tenant",         default="partner-team",
                        help="Target tenant from tenants.yml (default: partner-team)")
    parser.add_argument("--malicious-only", action="store_true")
    parser.add_argument("--benign-only",    action="store_true")
    parser.add_argument("--vendor",         help="crowdstrike | sentinelone | carbonblack | defender | azure_audit | aws_cloudtrail | onepassword")
    parser.add_argument("--detection",      help="Filter by detection rule ID")
    parser.add_argument("--scenario",       help="Filter by scenario tag")
    parser.add_argument("--killchain",      action="store_true", help="Send full 3-stage kill chain with 8-min stage delays")
    parser.add_argument("--dry-run",        action="store_true")
    parser.add_argument("--events-file",    default=str(EVENTS_FILE))
    parser.add_argument("--delay",          type=float, default=DELAY_BETWEEN_EVENTS)
    args = parser.parse_args()

    # Load tenant config
    global CONFIG
    CONFIG = load_tenant_config(args.tenant)

    events_path = Path(args.events_file)
    if not events_path.exists():
        print(f"❌ Events file not found: {events_path}")
        sys.exit(1)

    all_events = load_events(events_path)

    if args.killchain:
        kc_events = [e for e in all_events if (e.get("scenario") or "").startswith("killchain")]
        if not kc_events:
            print("⚠️  No events with scenario: killchain_stage_1/2/3 found.")
            sys.exit(1)
        print(f"\n{'='*60}")
        print("  KILL CHAIN MODE — Ransomware Precursor")
        print(f"{'='*60}")
        print(f"  Stages       : S1 LOLBin → 1Password Vault Harvest → AWS Backup Destruction")
        print(f"  Stage delay  : {int(KILLCHAIN_STAGE_DELAY)}s ({int(KILLCHAIN_STAGE_DELAY/60)} min)")
        print(f"  Total time   : ~{int(KILLCHAIN_STAGE_DELAY * 2 / 60)} minutes end to end")
        print(f"  Tenant       : {args.tenant}")
        print(f"  Mode         : {'DRY RUN' if args.dry_run else 'LIVE'}")
        print(f"{'='*60}")
        if not args.dry_run:
            confirm = input("\nSend kill chain events to Panther? (y/N): ").strip().lower()
            if confirm not in ("y", "yes"):
                print("Aborted.")
                sys.exit(0)
        ok, fail = send_killchain(kc_events, args.dry_run, args.delay)
    else:
        events = filter_events(all_events, args)
        if not events:
            print("No events matched the specified filters.")
            sys.exit(0)

        malicious_count = sum(1 for e in events if e.get("malicious"))
        benign_count    = len(events) - malicious_count

        print(f"\n{'='*60}")
        print("  EDR + Identity + Cloud Test Event Sender")
        print(f"{'='*60}")
        print(f"  Events file  : {events_path.name}")
        print(f"  Total events : {len(events)}  ({malicious_count} malicious, {benign_count} benign)")
        print(f"  Mode         : {'DRY RUN' if args.dry_run else 'LIVE'}")
        print(f"  Tenant       : {args.tenant}")
        print(f"  Started      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}\n")

        if not args.dry_run:
            confirm = input("Send events to Panther? (y/N): ").strip().lower()
            if confirm not in ("y", "yes"):
                print("Aborted.")
                sys.exit(0)

        ok, fail = send_batch(events, args.dry_run, args.delay)

    print(f"\n{'='*60}")
    print("  SUMMARY")
    print(f"{'='*60}")
    print(f"  ✅ Sent OK  : {ok}")
    print(f"  ❌ Failed   : {fail}")
    print(f"  Total       : {ok + fail}")

    if not args.dry_run and ok > 0:
        print(f"\n  Check your Panther console for alerts:")
        print(f"  Investigate > Alerts — filter last 30 minutes\n")

    sys.exit(1 if fail > 0 else 0)


if __name__ == "__main__":
    main()