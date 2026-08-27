#!/usr/bin/env python3
"""
Test script to verify Panther webhook connection for Okta logs.
This script sends a test payload to verify the webhook is working correctly.
"""

import json
import requests
import logging
from datetime import datetime, timezone
from config import PANTHER_OKTA_WEBHOOK_URL, PANTHER_OKTA_WEBHOOK_SECRET

def test_webhook_connection():
    """Test the webhook connection with a sample Okta log entry."""
    
    # Create a test Okta log entry
    test_log = {
        "uuid": "test-uuid-12345",
        "published": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
        "eventType": "user.session.start",
        "version": "0",
        "severity": "INFO",
        "legacyEventType": "core.user_auth.login_success",
        "displayMessage": "User login to Okta - TEST",
        "actor": {
            "id": "test-user-id",
            "type": "User",
            "alternateId": "test.user@example.com",
            "displayName": "Test User"
        },
        "client": {
            "userAgent": {
                "browser": "CHROME",
                "os": "Mac OS X",
                "rawUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36"
            },
            "geographicalContext": {
                "geolocation": {
                    "lat": 37.7852,
                    "lon": -122.3874
                },
                "city": "San Francisco",
                "state": "California",
                "country": "United States",
                "postalCode": "94105"
            },
            "zone": "null",
            "ipAddress": "127.0.0.1",
            "device": "Computer"
        },
        "request": {
            "ipChain": [
                {
                    "ip": "127.0.0.1",
                    "geographicalContext": {
                        "geolocation": {
                            "lat": 37.7852,
                            "lon": -122.3874
                        },
                        "city": "San Francisco",
                        "state": "California",
                        "country": "United States",
                        "postalCode": "94105"
                    },
                    "version": "V4"
                }
            ]
        },
        "outcome": {
            "result": "SUCCESS"
        },
        "transaction": {
            "id": "test-transaction-id",
            "type": "WEB",
            "detail": {}
        },
        "debugContext": {
            "debugData": {
                "requestUri": "/api/v1/authn",
                "threatSuspected": "false",
                "url": "/api/v1/authn?",
                "deviceFingerprint": "test-fingerprint",
                "requestId": "test-request-id",
                "origin": "https://test.okta.com"
            }
        },
        "authenticationContext": {
            "authenticationStep": 0,
            "externalSessionId": "test-session-id"
        },
        "securityContext": {}
    }
    
    # Prepare headers with okta-header
    headers = {
        'Content-Type': 'application/json',
        'okta-header': PANTHER_OKTA_WEBHOOK_SECRET,
        'User-Agent': 'Panther-Test-Scenario/1.0'
    }
    
    # Test payload (array of logs)
    test_payload = [test_log]
    
    print("🧪 Testing Panther Webhook Connection")
    print("=" * 50)
    print(f"Webhook URL: {PANTHER_OKTA_WEBHOOK_URL}")
    print(f"Header: okta-header = {PANTHER_OKTA_WEBHOOK_SECRET[:8]}...")
    print(f"Test payload: {len(test_payload)} log entry")
    print()
    
    # Set up logging
    logging.basicConfig(
        format='[%(asctime)s %(levelname)-8s] %(message)s',
        level=logging.INFO,
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    try:
        print("📤 Sending test payload to webhook...")
        response = requests.post(
            PANTHER_OKTA_WEBHOOK_URL,
            json=test_payload,
            headers=headers,
            timeout=30
        )
        
        print(f"📥 Response Status Code: {response.status_code}")
        print(f"📥 Response Headers: {dict(response.headers)}")
        
        if response.text:
            print(f"📥 Response Body: {response.text}")
        
        if response.status_code == 200:
            print("✅ Webhook test SUCCESSFUL!")
            print("   The webhook is working correctly and accepted the test payload.")
            return True
        else:
            print(f"❌ Webhook test FAILED!")
            print(f"   Status code: {response.status_code}")
            print(f"   Response: {response.text}")
            return False
            
    except requests.exceptions.Timeout:
        print("❌ Webhook test FAILED - Request timed out")
        return False
    except requests.exceptions.ConnectionError as e:
        print(f"❌ Webhook test FAILED - Connection error: {e}")
        return False
    except requests.exceptions.RequestException as e:
        print(f"❌ Webhook test FAILED - Request error: {e}")
        return False
    except Exception as e:
        print(f"❌ Webhook test FAILED - Unexpected error: {e}")
        return False

def main():
    """Main function to run the webhook test."""
    print("🚀 Panther Okta Webhook Connection Test")
    print("=" * 50)
    
    success = test_webhook_connection()
    
    print("\n" + "=" * 50)
    if success:
        print("🎉 Webhook connection test PASSED!")
        print("   You can now run the Okta test scenarios:")
        print("   - python 01_send_victim_okta.py")
        print("   - python 03_send_attacker_okta.py")
    else:
        print("💥 Webhook connection test FAILED!")
        print("   Please check your webhook configuration:")
        print("   - Verify the webhook URL is correct")
        print("   - Verify the shared secret is correct")
        print("   - Check that the webhook is enabled in Panther")
    
    return success

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
