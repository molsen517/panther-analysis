#!/usr/bin/env python3
"""
Send victim CloudTrail logs to Panther.
This script sends legitimate AWS console login data from the victim's perspective.
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
    # Use current time if panther compromise datetime is not specified
    panther_datetime = PANTHER_COMPROMISE_DATETIME or datetime.now(timezone.utc).isoformat()
    yaml_file = f"{TEST_SCENARIOS_DIR}/victim_cloudtrail.yml"

    print("Sending victim CloudTrail logs (legitimate AWS console activity)...")
    print(f"Webhook URL: {PANTHER_CLOUDTRAIL_WEBHOOK_URL}")

    logging.basicConfig(
        format='[%(asctime)s %(levelname)-8s] %(message)s',
        level=logging.INFO,
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    success = send_cloudtrail_logs_to_webhook(
        yaml_file,
        PANTHER_CLOUDTRAIL_WEBHOOK_URL,
        PANTHER_CLOUDTRAIL_WEBHOOK_SECRET,
        COMPROMISE_DATETIME,
        panther_datetime
    )

    if success:
        print("✅ Successfully sent victim CloudTrail logs")
    else:
        print("❌ Failed to send victim CloudTrail logs")
        sys.exit(1)

if __name__ == "__main__":
    main()