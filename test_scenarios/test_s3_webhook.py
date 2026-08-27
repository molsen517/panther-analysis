#!/usr/bin/env python3
"""
Test script to verify Panther webhook connection for S3 Server Access logs.
This script sends a test payload to verify the S3 webhook is working correctly.
"""

import json
import requests
import logging
from datetime import datetime, timezone
from config import PANTHER_S3_WEBHOOK_URL, PANTHER_S3_WEBHOOK_SECRET

def test_s3_webhook_connection():
    """Test the S3 webhook connection with a sample S3 Server Access log entry."""
    
    # Create a test S3 Server Access log entry
    test_log = "79a59df900bb44eeed96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be test-bucket [01/Nov/2020:10:43:07 +0000] 127.0.0.1 arn:aws:iam::123456789012:user/test-user DD6CC733AEXAMPLE REST.GET.OBJECT test-file.pdf \"GET /test-file.pdf HTTP/1.1\" 200 - - 4406583 41754 28 \"-\" \"S3Console/0.4\" - 10S62Zv81kBW7BB6SX4XJ48o6kpcl6LPwEoizZQQxJd5qDSCTLX0TgS37kYUBKQW3+bPdrg1234= SigV4 ECDHE-RSA-AES128-SHA AuthHeader test-bucket.s3.amazonaws.com TLSV1.1"
    
    # Prepare headers with okta-header
    headers = {
        'Content-Type': 'application/json',
        'okta-header': PANTHER_S3_WEBHOOK_SECRET,
        'User-Agent': 'Panther-Test-Scenario/1.0'
    }
    
    # Test payload (array of logs)
    test_payload = [test_log]
    
    print("🧪 Testing Panther S3 Webhook Connection")
    print("=" * 50)
    print(f"Webhook URL: {PANTHER_S3_WEBHOOK_URL}")
    print(f"Header: okta-header = {PANTHER_S3_WEBHOOK_SECRET[:8]}...")
    print(f"Test payload: {len(test_payload)} S3 log entry")
    print()
    
    # Set up logging
    logging.basicConfig(
        format='[%(asctime)s %(levelname)-8s] %(message)s',
        level=logging.INFO,
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    try:
        print("📤 Sending test S3 payload to webhook...")
        response = requests.post(
            PANTHER_S3_WEBHOOK_URL,
            json=test_payload,
            headers=headers,
            timeout=30
        )
        
        print(f"📥 Response Status Code: {response.status_code}")
        print(f"📥 Response Headers: {dict(response.headers)}")
        
        if response.text:
            print(f"📥 Response Body: {response.text}")
        
        if response.status_code == 200:
            print("✅ S3 Webhook test SUCCESSFUL!")
            print("   The S3 webhook is working correctly and accepted the test payload.")
            return True
        else:
            print(f"❌ S3 Webhook test FAILED!")
            print(f"   Status code: {response.status_code}")
            print(f"   Response: {response.text}")
            return False
            
    except requests.exceptions.Timeout:
        print("❌ S3 Webhook test FAILED - Request timed out")
        return False
    except requests.exceptions.ConnectionError as e:
        print(f"❌ S3 Webhook test FAILED - Connection error: {e}")
        return False
    except requests.exceptions.RequestException as e:
        print(f"❌ S3 Webhook test FAILED - Request error: {e}")
        return False
    except Exception as e:
        print(f"❌ S3 Webhook test FAILED - Unexpected error: {e}")
        return False

def main():
    """Main function to run the S3 webhook test."""
    print("🚀 Panther S3 Server Access Webhook Connection Test")
    print("=" * 50)
    
    success = test_s3_webhook_connection()
    
    print("\n" + "=" * 50)
    if success:
        print("🎉 S3 Webhook connection test PASSED!")
        print("   You can now run the S3 test scenario:")
        print("   - python 05_send_attacker_s3_access.py")
    else:
        print("💥 S3 Webhook connection test FAILED!")
        print("   Please check your S3 webhook configuration:")
        print("   - Verify the webhook URL is correct")
        print("   - Verify the shared secret is correct")
        print("   - Check that the webhook is enabled in Panther")
    
    return success

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
