#!/usr/bin/env python3
"""
EDR UDM Test Event Sender
Reads sample events from edr_test_events.yml and sends them to
Panther HTTP log sources for detection testing.

Usage:
    python send_edr_events.py                        # send all events
    python send_edr_events.py --malicious-only       # only events that should trigger detections
    python send_edr_events.py --benign-only          # only benign/baseline events
    python send_edr_events.py --vendor crowdstrike   # filter by vendor
    python send_edr_events.py --detection EDR.UDM.Credential.Dumping.Tool
    python send_edr_events.py --dry-run              # print events without sending
"""

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import urllib.request
import urllib.error
import yaml

# ─────────────────────────────────────────────
#  CONFIG — update with your Panther HTTP source URLs
#  Found in: Panther Console > Configure > Log Sources > [source] > Setup
# ─────────────────────────────────────────────
CONFIG = {
    "crowdstrike": {
        "url":   "https://logs.beazley-security.runpanther.net/http/6e7c38d7-32e2-4069-ba6a-15d7cff929b8",
        "token": "02ce567b-4f27-4c4e-844d-24a26030f28a",
    },
    "sentinelone": {
        "url":   "https://logs.beazley-security.runpanther.net/http/81f94a2f-bf2a-4a70-b35f-478651a240f6",
        "token": "3d76b737-7514-4fe8-93b2-797899c4f0c4",
    },
    "carbonblack": {
        "url":   "https://logs.beazley-security.runpanther.net/http/e6f974f3-8c30-4119-a507-0766227f013e",
        "token": "086cd112-facf-460e-941f-cd59299a949c",
    },
    "defender": {
        "url":   "https://logs.beazley-security.runpanther.net/http/938c95b7-ec3f-4126-bb39-37ae70002c93",
        "token": "a7d033b8-90b6-4793-ad71-c53e07e76af0",
    },
}

# Map log_type prefixes to config keys
LOG_TYPE_VENDOR_MAP = {
    "Crowdstrike":           "crowdstrike",
    "SentinelOne":           "sentinelone",
    "CarbonBlack":           "carbonblack",
    "MicrosoftDefenderXDR":  "defender",
}

EVENTS_FILE = Path(__file__).parent / "edr_test_events.yml"

# Required fields injected per log type if missing from the event payload
REQUIRED_FIELDS = {
    "SentinelOne": {
        "account.id":  "beazley-s1-account-01",   # SentinelOne account ID
        # event.time is injected dynamically at send time (see send_event)
    },
}
DELAY_BETWEEN_EVENTS = 0.3  # seconds


# ─────────────────────────────────────────────
#  Core send function
# ─────────────────────────────────────────────

def send_event(event_data: dict, vendor: str, dry_run: bool = False) -> bool:
    """POST a single event to the appropriate Panther HTTP source."""
    cfg = CONFIG.get(vendor)
    if not cfg:
        print(f"  ⚠️  No config found for vendor '{vendor}' — skipping")
        return False

    if dry_run:
        print(f"  [DRY RUN] Would POST to {cfg['url'][:60]}...")
        print(f"  Payload: {json.dumps(event_data, indent=2)[:200]}...")
        return True

    payload = json.dumps(event_data).encode("utf-8")
    req = urllib.request.Request(
        cfg["url"],
        data=payload,
        headers={
            "Content-Type": "application/json",
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


def filter_events(events, args) -> list[dict]:
    filtered = events

    if args.malicious_only:
        filtered = [e for e in filtered if e.get("malicious")]
    elif args.benign_only:
        filtered = [e for e in filtered if not e.get("malicious")]

    if args.vendor:
        filtered = [e for e in filtered if get_vendor(e["event"].get("p_log_type", "")) == args.vendor.lower()]

    if args.scenario:
        filtered = [e for e in filtered if e.get("scenario") == args.scenario]

    if args.detection:
        filtered = [e for e in filtered if e.get("expected_detection") == args.detection]

    return filtered


# ─────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────


def prepare_payload(raw: dict, log_type: str, now_iso: str) -> dict:
    """
    Ensure each vendor's payload meets Panther schema requirements.
    Handles nested structures (CrowdStrike event/metadata, Defender properties)
    and injects required fields so the YAML stays clean.
    """

    # ── SentinelOne.DeepVisibilityV2 ─────────────────────────────────────
    # event.time must be a Unix epoch integer (milliseconds), not an ISO string
    if log_type.startswith("SentinelOne"):
        raw.setdefault("account.id", "beazley-s1-account-01")
        # Convert event.time to Unix ms if it's an ISO string
        et = raw.get("event.time")
        if et is None:
            raw["event.time"] = int(datetime.now(timezone.utc).timestamp() * 1000)
        elif isinstance(et, str):
            from datetime import datetime as _dt
            try:
                parsed = _dt.fromisoformat(et.replace("Z", "+00:00"))
                raw["event.time"] = int(parsed.timestamp() * 1000)
            except Exception:
                raw["event.time"] = int(datetime.now(timezone.utc).timestamp() * 1000)
        return raw

    # ── CarbonBlack.EndpointEvent ─────────────────────────────────────────
    if log_type.startswith("CarbonBlack"):
        raw.setdefault("action",           "ACTION_CREATE_PROCESS")
        raw.setdefault("device_timestamp", now_iso)
        raw.setdefault("org_key",          "BEAZLEY-CB-ORG")
        raw.setdefault("device_id",        "7245001")
        raw.setdefault("device_os",        "WINDOWS")
        raw.setdefault("schema",           1)
        return raw

    # ── MicrosoftDefenderXDR.AdvancedHunting ─────────────────────────────
    if log_type.startswith("MicrosoftDefenderXDR"):
        # If the YAML already has the correct top-level wrapper fields, pass through
        if "properties" in raw:
            raw.setdefault("time",     now_iso)
            raw.setdefault("tenantId", "beazley-tenant-001")
            raw.setdefault("category", "AdvancedHunting-DeviceProcessEvents")
            return raw
        # Otherwise wrap all event fields inside properties
        top_level = {"time", "tenantId", "category"}
        properties = {k: v for k, v in raw.items() if k not in top_level}
        payload = {k: v for k, v in raw.items() if k in top_level}
        payload.setdefault("time",     now_iso)
        payload.setdefault("tenantId", "beazley-tenant-001")
        payload.setdefault("category", "AdvancedHunting-DeviceProcessEvents")
        payload["properties"] = properties
        return payload

    # ── Crowdstrike.EventStreams ───────────────────────────────────────────
    if log_type.startswith("Crowdstrike"):
        # If YAML already has correct nested metadata + event keys, pass through
        if "metadata" in raw and "event" in raw:
            return raw
        # Otherwise wrap process fields inside event{} and inject metadata{}
        skip = {"metadata", "event"}
        event_data = {k: v for k, v in raw.items() if k not in skip}
        return {
            "metadata": {
                "customerIDString": "BEAZLEY-CS-CID-001",
                "eventType":        "DetectionSummaryEvent",
                "eventCreationTime": 1716134400000,
                "version":          "1.0",
                "offset":           1,
            },
            "event": event_data,
        }

    # ── Unknown vendor — pass through as-is ──────────────────────────────
    return raw


def main():
    parser = argparse.ArgumentParser(description="Send EDR UDM test events to Panther")
    parser.add_argument("--malicious-only", action="store_true", help="Only send events expected to trigger detections")
    parser.add_argument("--benign-only",    action="store_true", help="Only send benign/baseline events")
    parser.add_argument("--vendor",         help="Filter by vendor: crowdstrike | sentinelone | carbonblack | defender")
    parser.add_argument("--detection",      help="Filter by detection rule ID")
    parser.add_argument("--dry-run",        action="store_true", help="Print events without sending")
    parser.add_argument("--events-file",    default=str(EVENTS_FILE), help="Path to events YAML file")
    parser.add_argument("--scenario",      help="Filter by scenario tag (e.g. process_tree_demo)")
    parser.add_argument("--delay",          type=float, default=DELAY_BETWEEN_EVENTS, help="Delay between events (seconds)")
    args = parser.parse_args()

    events_path = Path(args.events_file)
    if not events_path.exists():
        print(f"❌ Events file not found: {events_path}")
        sys.exit(1)

    events = load_events(events_path)
    events = filter_events(events, args)

    if not events:
        print("No events matched the specified filters.")
        sys.exit(0)

    malicious_count = sum(1 for e in events if e.get("malicious"))
    benign_count    = len(events) - malicious_count

    print(f"\n{'='*60}")
    print("  EDR UDM Test Event Sender")
    print(f"{'='*60}")
    print(f"  Events file  : {events_path.name}")
    print(f"  Total events : {len(events)}  ({malicious_count} malicious, {benign_count} benign)")
    print(f"  Mode         : {'DRY RUN' if args.dry_run else 'LIVE'}")
    print(f"  Started      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    if not args.dry_run:
        confirm = input("Send events to Panther? (y/N): ").strip().lower()
        if confirm not in ("y", "yes"):
            print("Aborted.")
            sys.exit(0)

    sent_ok, sent_fail = 0, 0

    for i, entry in enumerate(events, 1):
        log_type  = entry["event"].get("p_log_type", "Unknown")
        vendor    = get_vendor(log_type)
        detection = entry.get("expected_detection", "—")
        label     = "🔴 MALICIOUS" if entry.get("malicious") else "🟢 BENIGN   "
        desc      = entry.get("description", "")

        print(f"[{i:02}/{len(events)}] {label}  {log_type:<40}  {desc}")
        if entry.get("malicious"):
            print(f"         Expected detection: {detection}")

        raw = entry["event"].copy()
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        log_type = raw.get("p_log_type", "")

        # Strip routing-only field — not part of any raw log schema
        raw.pop("p_log_type", None)

        event_payload = prepare_payload(raw, log_type, now_iso)

        ok = send_event(event_payload, vendor, dry_run=args.dry_run)
        if ok:
            sent_ok += 1
            if not args.dry_run:
                print(f"         ✅ Sent")
        else:
            sent_fail += 1

        if i < len(events):
            time.sleep(args.delay)

    print(f"\n{'='*60}")
    print("  SUMMARY")
    print(f"{'='*60}")
    print(f"  ✅ Sent OK  : {sent_ok}")
    print(f"  ❌ Failed   : {sent_fail}")
    print(f"  Total       : {len(events)}")

    if not args.dry_run and sent_ok > 0:
        print(f"\n  Check your Panther console for alerts:")
        print(f"  Investigate > Alerts — filter last 15 minutes\n")

    sys.exit(1 if sent_fail > 0 else 0)


if __name__ == "__main__":
    main()
