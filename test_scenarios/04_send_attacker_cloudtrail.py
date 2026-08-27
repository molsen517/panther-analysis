#!/usr/bin/env python3
"""
Send attacker CloudTrail logs to Panther.
This script sends malicious AWS activity including failed logins, user creation, and EC2 instance launches.
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
    yaml_file = f"{TEST_SCENARIOS_DIR}/attacker_cloudtrail.yml"

    print("Sending attacker CloudTrail logs (malicious AWS activity)...")
    print("  - Failed console logins")
    print("  - Successful console login")
    print("  - User creation (tracy_stone)")
    print("  - Policy attachments")
    print("  - Access key creation")
    print("  - EC2 instance launch")
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
        print("✅ Successfully sent attacker CloudTrail logs")
    else:
        print("❌ Failed to send attacker CloudTrail logs")
        sys.exit(1)

    if __name__ == "__main__":
        main()