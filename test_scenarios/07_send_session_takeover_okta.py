#!/usr/bin/env python3
"""
Send Okta session takeover test events (legit and attacker) to Panther via webhook.
This script sends the legitimate event, then the attacker event, each from its own YAML file.
"""

import sys
import logging
from datetime import datetime, timezone
from config import (
    COMPROMISE_DATETIME,
    PANTHER_COMPROMISE_DATETIME,
    PANTHER_OKTA_WEBHOOK_URL,
    PANTHER_OKTA_WEBHOOK_SECRET,
    TEST_SCENARIOS_DIR
)
from webhook_sender import send_okta_logs_to_webhook

def main():
    panther_datetime = PANTHER_COMPROMISE_DATETIME or datetime.now(timezone.utc).isoformat()
    legit_file = "session_takeover_okta_legit.yml"
    attack_file = "session_takeover_okta_attack.yml"

    print("Sending Okta session takeover test events (legit and attacker) to Panther webhook...")
    print(f"Webhook URL: {PANTHER_OKTA_WEBHOOK_URL}")

    logging.basicConfig(
        format='[%(asctime)s %(levelname)-8s] %(message)s',
        level=logging.INFO,
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    all_success = True
    for idx, yaml_file in enumerate([legit_file, attack_file], 1):
        print(f"Sending event {idx} from {yaml_file}...")
        try:
            success = send_okta_logs_to_webhook(
                yaml_file,
                PANTHER_OKTA_WEBHOOK_URL,
                PANTHER_OKTA_WEBHOOK_SECRET,
                COMPROMISE_DATETIME,
                panther_datetime
            )
            if not success:
                all_success = False
        except Exception as e:
            print(f"❌ Error sending event from {yaml_file}: {e}")
            all_success = False

    if all_success:
        print("✅ Successfully sent both Okta session takeover test events to webhook")
    else:
        print("❌ Failed to send one or more Okta session takeover test events to webhook")
        sys.exit(1)

if __name__ == "__main__":
    main()