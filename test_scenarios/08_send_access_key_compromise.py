#!/usr/bin/env python3
"""
Send AWS IAM access key compromise test events (normal and suspicious) to Panther via webhook.
This script sends both a normal and a suspicious AWS CloudTrail event, each from its own YAML file.
"""

import sys
import logging
from datetime import datetime, timezone
from config import (
    COMPROMISE_DATETIME,
    PANTHER_COMPROMISE_DATETIME,
    PANTHER_CLOUDTRAIL_WEBHOOK_URL,
    PANTHER_CLOUDTRAIL_WEBHOOK_SECRET,
    TEST_SCENARIOS_DIR
)
from webhook_sender import send_cloudtrail_logs_to_webhook

def main():
    panther_datetime = PANTHER_COMPROMISE_DATETIME or datetime.now(timezone.utc).isoformat()
    normal_file = "08_access_key_normal.yml"
    suspicious_file = "08_access_key_suspicious.yml"

    print("Sending AWS IAM access key compromise test events (normal and suspicious) to Panther webhook...")
    print(f"Webhook URL: {PANTHER_CLOUDTRAIL_WEBHOOK_URL}")

    logging.basicConfig(
        format='[%(asctime)s %(levelname)-8s] %(message)s',
        level=logging.INFO,
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    all_success = True
    for idx, yaml_file in enumerate([normal_file, suspicious_file], 1):
        print(f"Sending event {idx} from {yaml_file}...")
        try:
            success = send_cloudtrail_logs_to_webhook(
                yaml_file,
                PANTHER_CLOUDTRAIL_WEBHOOK_URL,
                PANTHER_CLOUDTRAIL_WEBHOOK_SECRET,
                COMPROMISE_DATETIME,
                panther_datetime
            )
            if not success:
                all_success = False
        except Exception as e:
            print(f"❌ Error sending event from {yaml_file}: {e}")
            all_success = False

    if all_success:
        print("✅ Successfully sent both AWS IAM access key test events to webhook")
    else:
        print("❌ Failed to send one or more AWS IAM access key test events to webhook")
        sys.exit(1)

if __name__ == "__main__":
    main()