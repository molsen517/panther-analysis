#!/usr/bin/env python3
"""
Webhook sender utility for sending Okta logs to Panther webhook endpoint.
"""

import json
import logging
import requests
import yaml
from datetime import datetime, timezone
from typing import List, Dict, Any

def send_okta_logs_to_webhook(yaml_file_path: str, webhook_url: str, webhook_secret: str, 
                             compromise_datetime: str, panther_compromise_datetime: str = None):
    """
    Send Okta logs from a YAML file to Panther webhook endpoint.
    
    Args:
        yaml_file_path: Path to the YAML file containing Okta logs
        webhook_url: Panther webhook URL
        webhook_secret: Shared secret for authentication
        compromise_datetime: Original compromise datetime
        panther_compromise_datetime: When to show the compromise in Panther (defaults to now)
    """
    
    # Load YAML data
    with open(yaml_file_path, 'r') as file:
        data = yaml.safe_load(file)
    
    logs = data.get('Logs', [])
    if not logs:
        logging.warning(f"No logs found in {yaml_file_path}")
        return False
    
    # Calculate time shift
    compromise_dt = datetime.fromisoformat(compromise_datetime.replace('Z', '+00:00'))
    if panther_compromise_datetime:
        panther_dt = datetime.fromisoformat(panther_compromise_datetime.replace('Z', '+00:00'))
    else:
        panther_dt = datetime.now(timezone.utc)
    
    time_shift = panther_dt - compromise_dt
    
    # Time shift the logs
    shifted_logs = time_shift_okta_logs(logs, time_shift)
    
    # Prepare headers
    headers = {
        'Content-Type': 'application/json',
        'okta-header': webhook_secret,
        'User-Agent': 'Panther-Test-Scenario/1.0'
    }
    
    # Send logs to webhook
    logging.info(f"Sending {len(shifted_logs)} Okta logs to webhook...")
    
    try:
        response = requests.post(
            webhook_url,
            json=shifted_logs,
            headers=headers,
            timeout=30
        )
        
        if response.status_code == 200:
            logging.info("✅ Successfully sent Okta logs to webhook")
            return True
        else:
            logging.error(f"❌ Webhook request failed with status {response.status_code}")
            logging.error(f"Response: {response.text}")
            return False
            
    except requests.exceptions.RequestException as e:
        logging.error(f"❌ Error sending to webhook: {e}")
        return False

def time_shift_okta_logs(logs: List[Dict[str, Any]], time_shift) -> List[Dict[str, Any]]:
    """
    Time shift Okta logs by the specified amount.
    
    Args:
        logs: List of Okta log entries
        time_shift: TimeDelta object representing the shift amount
        
    Returns:
        List of time-shifted log entries
    """
    shifted_logs = []
    
    for log in logs:
        # Create a copy of the log
        shifted_log = log.copy()
        
        # Shift the published timestamp
        if 'published' in shifted_log:
            original_time = datetime.fromisoformat(shifted_log['published'].replace('Z', '+00:00'))
            shifted_time = original_time + time_shift
            shifted_log['published'] = shifted_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        
        shifted_logs.append(shifted_log)
    
    return shifted_logs

def send_s3_logs_to_webhook(yaml_file_path: str, webhook_url: str, webhook_secret: str, 
                           compromise_datetime: str, panther_compromise_datetime: str = None):
    """
    Send S3 Server Access logs from a YAML file to Panther webhook endpoint.
    
    Args:
        yaml_file_path: Path to the YAML file containing S3 logs
        webhook_url: Panther webhook URL
        webhook_secret: Shared secret for authentication
        compromise_datetime: Original compromise datetime
        panther_compromise_datetime: When to show the compromise in Panther (defaults to now)
    """
    
    # Load YAML data
    with open(yaml_file_path, 'r') as file:
        data = yaml.safe_load(file)
    
    logs = data.get('Logs', [])
    if not logs:
        logging.warning(f"No logs found in {yaml_file_path}")
        return False
    
    # Calculate time shift
    compromise_dt = datetime.fromisoformat(compromise_datetime.replace('Z', '+00:00'))
    if panther_compromise_datetime:
        panther_dt = datetime.fromisoformat(panther_compromise_datetime.replace('Z', '+00:00'))
    else:
        panther_dt = datetime.now(timezone.utc)
    
    time_shift = panther_dt - compromise_dt
    
    # Time shift the logs
    shifted_logs = time_shift_s3_logs(logs, time_shift)
    
    # Prepare headers
    headers = {
        'Content-Type': 'application/json',
        'okta-header': webhook_secret,
        'User-Agent': 'Panther-Test-Scenario/1.0'
    }
    
    # Send logs to webhook
    logging.info(f"Sending {len(shifted_logs)} S3 logs to webhook...")
    
    try:
        response = requests.post(
            webhook_url,
            json=shifted_logs,
            headers=headers,
            timeout=30
        )
        
        if response.status_code == 200:
            logging.info("✅ Successfully sent S3 logs to webhook")
            return True
        else:
            logging.error(f"❌ Webhook request failed with status {response.status_code}")
            logging.error(f"Response: {response.text}")
            return False
            
    except requests.exceptions.RequestException as e:
        logging.error(f"❌ Error sending to webhook: {e}")
        return False

def send_vpc_logs_to_webhook(yaml_file_path: str, webhook_url: str, webhook_secret: str, 
                            compromise_datetime: str, panther_compromise_datetime: str = None):
    """
    Send VPC Flow logs from a YAML file to Panther webhook endpoint.
    
    Args:
        yaml_file_path: Path to the YAML file containing VPC logs
        webhook_url: Panther webhook URL
        webhook_secret: Shared secret for authentication
        compromise_datetime: Original compromise datetime
        panther_compromise_datetime: When to show the compromise in Panther (defaults to now)
    """
    
    # Load YAML data
    with open(yaml_file_path, 'r') as file:
        data = yaml.safe_load(file)
    
    logs = data.get('Logs', [])
    if not logs:
        logging.warning(f"No logs found in {yaml_file_path}")
        return False
    
    # Calculate time shift
    compromise_dt = datetime.fromisoformat(compromise_datetime.replace('Z', '+00:00'))
    if panther_compromise_datetime:
        panther_dt = datetime.fromisoformat(panther_compromise_datetime.replace('Z', '+00:00'))
    else:
        panther_dt = datetime.now(timezone.utc)
    
    time_shift = panther_dt - compromise_dt
    
    # Time shift the logs
    shifted_logs = time_shift_vpc_logs(logs, time_shift)
    
    # Prepare headers
    headers = {
        'Content-Type': 'application/json',
        'okta-header': webhook_secret,
        'User-Agent': 'Panther-Test-Scenario/1.0'
    }
    
    # Send logs to webhook
    logging.info(f"Sending {len(shifted_logs)} VPC logs to webhook...")
    
    try:
        response = requests.post(
            webhook_url,
            json=shifted_logs,
            headers=headers,
            timeout=30
        )
        
        if response.status_code == 200:
            logging.info("✅ Successfully sent VPC logs to webhook")
            return True
        else:
            logging.error(f"❌ Webhook request failed with status {response.status_code}")
            logging.error(f"Response: {response.text}")
            return False
            
    except requests.exceptions.RequestException as e:
        logging.error(f"❌ Error sending to webhook: {e}")
        return False

def time_shift_s3_logs(logs: List[str], time_shift) -> List[str]:
    """
    Time shift S3 Server Access logs by the specified amount.
    
    Args:
        logs: List of S3 log entries (raw format)
        time_shift: TimeDelta object representing the shift amount
        
    Returns:
        List of time-shifted log entries
    """
    shifted_logs = []
    
    for log in logs:
        # S3 logs are space-separated, timestamp is in [dd/MMM/yyyy:HH:mm:ss +0000] format
        # Find the timestamp pattern and shift it
        import re
        
        # Pattern to match [dd/MMM/yyyy:HH:mm:ss +0000]
        timestamp_pattern = r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} \+0000)\]'
        
        def shift_timestamp(match):
            timestamp_str = match.group(1)
            # Parse the timestamp
            original_time = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')
            shifted_time = original_time + time_shift
            return f"[{shifted_time.strftime('%d/%b/%Y:%H:%M:%S +0000')}]"
        
        shifted_log = re.sub(timestamp_pattern, shift_timestamp, log)
        shifted_logs.append(shifted_log)
    n
    return shifted_logs

def time_shift_vpc_logs(logs: List[str], time_shift) -> List[str]:
    """
    Time shift VPC Flow logs by the specified amount.
    
    Args:
        logs: List of VPC log entries (raw format)
        time_shift: TimeDelta object representing the shift amount
        
    Returns:
        List of time-shifted log entries
    """
    shifted_logs = []
    
    for log in logs:
        # VPC logs are space-separated, timestamps are at positions 10 and 11 (start and end times)
        log_parts = log.split(' ')
        
        if len(log_parts) >= 12:
            # Shift start time (position 10)
            start_timestamp = int(log_parts[10])
            start_time = datetime.fromtimestamp(start_timestamp, tz=timezone.utc)
            shifted_start_time = start_time + time_shift
            log_parts[10] = str(int(shifted_start_time.timestamp()))
            
            # Shift end time (position 11)
            end_timestamp = int(log_parts[11])
            end_time = datetime.fromtimestamp(end_timestamp, tz=timezone.utc)
            shifted_end_time = end_time + time_shift
            log_parts[11] = str(int(shifted_end_time.timestamp()))
            
            shifted_log = ' '.join(log_parts)
            shifted_logs.append(shifted_log)
        else:
            # If log format is unexpected, keep as is
            shifted_logs.append(log)
    
    return shifted_logs

def main():
    """Test function for the webhook sender."""
    import sys
    from config import (
        PANTHER_OKTA_WEBHOOK_URL,
        PANTHER_OKTA_WEBHOOK_SECRET,
        COMPROMISE_DATETIME,
        PANTHER_COMPROMISE_DATETIME
    )
    
    if len(sys.argv) != 2:
        print("Usage: python webhook_sender.py <yaml_file_path>")
        sys.exit(1)
    
    yaml_file = sys.argv[1]
    
    logging.basicConfig(
        format='[%(asctime)s %(levelname)-8s] %(message)s',
        level=logging.INFO,
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    success = send_okta_logs_to_webhook(
        yaml_file,
        PANTHER_WEBHOOK_URL,
        PANTHER_WEBHOOK_SECRET,
        COMPROMISE_DATETIME,
        PANTHER_COMPROMISE_DATETIME
    )
    
    if success:
        print("✅ Webhook send completed successfully")
    else:
        print("❌ Webhook send failed")
        sys.exit(1)

if __name__ == "__main__":
    main()
