#!/usr/bin/env python3
"""
Test script to verify Panther webhook connection for VPC Flow logs.
This script sends a test payload to verify the VPC webhook is working correctly.
"""

import json
import requests
import logging
from datetime import datetime, timezone
from config import PANTHER_VPC_WEBHOOK_URL, PANTHER_VPC_WEBHOOK_SECRET

def test_vpc_webhook_connection():
    """Test the VPC webhook connection with a sample VPC Flow log entry."""
    
    # Create a test VPC Flow log entry
    # Format: version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status
    current_time = int(datetime.now(timezone.utc).timestamp())
    test_log = f"2 123456789012 eni-0b13344793d4fde67 127.0.0.1 172.31.77.31 48316 22 6 19 7119 {current_time} {current_time + 16} ACCEPT OK"
    
    # Prepare headers with okta-header
    headers = {
        'Content-Type': 'application/json',
        'okta-header': PANTHER_VPC_WEBHOOK_SECRET,
        'User-Agent': 'Panther-Test-Scenario/1.0'
    }
    
    # Test payload (array of logs)
    test_payload = [test_log]
    
    print("🧪 Testing Panther VPC Webhook Connection")
    print("=" * 50)
    print(f"Webhook URL: {PANTHER_VPC_WEBHOOK_URL}")
    print(f"Header: okta-header = {PANTHER_VPC_WEBHOOK_SECRET[:8]}...")
    print(f"Test payload: {len(test_payload)} VPC log entry")
    print()
    
    # Set up logging
    logging.basicConfig(
        format='[%(asctime)s %(levelname)-8s] %(message)s',
        level=logging.INFO,
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    try:
        print("📤 Sending test VPC payload to webhook...")
        response = requests.post(
            PANTHER_VPC_WEBHOOK_URL,
            json=test_payload,
            headers=headers,
            timeout=30
        )
        
        print(f"📥 Response Status Code: {response.status_code}")
        print(f"📥 Response Headers: {dict(response.headers)}")
        
        if response.text:
            print(f"📥 Response Body: {response.text}")
        
        if response.status_code == 200:
            print("✅ VPC Webhook test SUCCESSFUL!")
            print("   The VPC webhook is working correctly and accepted the test payload.")
            return True
        else:
            print(f"❌ VPC Webhook test FAILED!")
            print(f"   Status code: {response.status_code}")
            print(f"   Response: {response.text}")
            return False
            
    except requests.exceptions.Timeout:
        print("❌ VPC Webhook test FAILED - Request timed out")
        return False
    except requests.exceptions.ConnectionError as e:
        print(f"❌ VPC Webhook test FAILED - Connection error: {e}")
        return False
    except requests.exceptions.RequestException as e:
        print(f"❌ VPC Webhook test FAILED - Request error: {e}")
        return False
    except Exception as e:
        print(f"❌ VPC Webhook test FAILED - Unexpected error: {e}")
        return False

def main():
    """Main function to run the VPC webhook test."""
    print("🚀 Panther VPC Flow Webhook Connection Test")
    print("=" * 50)
    
    success = test_vpc_webhook_connection()
    
    print("\n" + "=" * 50)
    if success:
        print("🎉 VPC Webhook connection test PASSED!")
        print("   You can now run the VPC test scenario:")
        print("   - python 06_send_attacker_vpc.py")
    else:
        print("💥 VPC Webhook connection test FAILED!")
        print("   Please check your VPC webhook configuration:")
        print("   - Verify the webhook URL is correct")
        print("   - Verify the shared secret is correct")
        print("   - Check that the webhook is enabled in Panther")
    
    return success

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
