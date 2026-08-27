#!/usr/bin/env python3
"""
Send attacker Okta logs to Panther via webhook.
This script sends failed login attempts from the attacker's perspective.
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
    """Send attacker Okta logs to Panther webhook."""
    
    # Use current time if panther compromise datetime is not specified
    panther_datetime = PANTHER_COMPROMISE_DATETIME
    if panther_datetime is None:
        panther_datetime = datetime.now(timezone.utc).isoformat()
    
    yaml_file = f"{TEST_SCENARIOS_DIR}/attacker_okta.yml"
    
    print("Sending attacker Okta logs (failed login attempts from Romania) to Panther webhook...")
    print(f"Webhook URL: {PANTHER_OKTA_WEBHOOK_URL}")
    print(f"YAML file: {yaml_file}")
    
    # Set up logging
    logging.basicConfig(
        format='[%(asctime)s %(levelname)-8s] %(message)s',
        level=logging.INFO,
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    try:
        success = send_okta_logs_to_webhook(
            yaml_file,
            PANTHER_OKTA_WEBHOOK_URL,
            PANTHER_OKTA_WEBHOOK_SECRET,
            COMPROMISE_DATETIME,
            panther_datetime
        )
        
        if success:
            print("✅ Successfully sent attacker Okta logs to webhook")
        else:
            print("❌ Failed to send attacker Okta logs to webhook")
            sys.exit(1)
            
    except Exception as e:
        print(f"❌ Error sending attacker Okta logs: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
