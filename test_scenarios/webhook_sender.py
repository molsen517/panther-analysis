import json
import logging
import requests
import yaml
from datetime import datetime, timezone
import copy
import re

def send_okta_logs_to_webhook(yaml_file_path: str, webhook_url: str, webhook_secret: str, 
                             compromise_datetime: str, panther_compromise_datetime: str = None):
    """
    Send Okta logs from a YAML file to Panther webhook endpoint.
    """
    with open(yaml_file_path, 'r') as file:
        data = yaml.safe_load(file)
    logs = data.get('Logs', [])
    if not logs:
        logging.warning(f"No logs found in {yaml_file_path}")
        return False

    compromise_dt = datetime.fromisoformat(compromise_datetime.replace('Z', '+00:00'))
    if panther_compromise_datetime:
        panther_dt = datetime.fromisoformat(panther_compromise_datetime.replace('Z', '+00:00'))
    else:
        panther_dt = datetime.now(timezone.utc)
    time_shift = panther_dt - compromise_dt

    shifted_logs = []
    for log in logs:
        shifted_log = log.copy()
        if 'published' in shifted_log:
            original_time = datetime.fromisoformat(shifted_log['published'].replace('Z', '+00:00'))
            shifted_time = original_time + time_shift
            shifted_log['published'] = shifted_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        shifted_logs.append(shifted_log)

    headers = {
        'Content-Type': 'application/json',
        'okta-header': webhook_secret,
        'User-Agent': 'Panther-Test-Scenario/1.0'
    }

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
    except Exception as e:
        logging.error(f"❌ Error sending to webhook: {e}")
        return False

def send_cloudtrail_logs_to_webhook(yaml_file_path: str, webhook_url: str, webhook_secret: str, 
                                    compromise_datetime: str, panther_compromise_datetime: str = None):
    """
    Send AWS CloudTrail logs from a YAML file to Panther webhook endpoint.
    """
    with open(yaml_file_path, 'r') as file:
        data = yaml.safe_load(file)

    logs = data.get('Logs', [])
    if not logs:
        logging.warning(f"No logs found in {yaml_file_path}")
        return False

    compromise_dt = datetime.fromisoformat(compromise_datetime.replace('Z', '+00:00'))
    if panther_compromise_datetime:
        panther_dt = datetime.fromisoformat(panther_compromise_datetime.replace('Z', '+00:00'))
    else:
        panther_dt = datetime.now(timezone.utc)

    time_shift = panther_dt - compromise_dt

    shifted_logs = []
    for log in logs:
        shifted_log = copy.deepcopy(log)
        for time_field in ['eventTime', 'p_event_time']:
            if time_field in shifted_log:
                try:
                    try:
                        original_time = datetime.strptime(shifted_log[time_field], '%Y-%m-%dT%H:%M:%SZ')
                    except ValueError:
                        original_time = datetime.strptime(shifted_log[time_field], '%Y-%m-%d %H:%M:%S.%f')
                    shifted_time = original_time + time_shift
                    if time_field == 'eventTime':
                        shifted_log[time_field] = shifted_time.strftime('%Y-%m-%dT%H:%M:%SZ')
                    else:
                        shifted_log[time_field] = shifted_time.strftime('%Y-%m-%d %H:%M:%S.%f')
                except Exception:
                    pass
        shifted_logs.append(shifted_log)

    headers = {
        'Content-Type': 'application/json',
        'Authorization': f"Bearer {webhook_secret}",
        'User-Agent': 'Panther-Test-Scenario/1.0'
    }

    logging.info(f"Sending {len(shifted_logs)} CloudTrail logs to webhook...")

    try:
        response = requests.post(
            webhook_url,
            json=shifted_logs,
            headers=headers,
            timeout=30
        )

        if response.status_code == 200:
            logging.info("✅ Successfully sent CloudTrail logs to webhook")
            return True
        else:
            logging.error(f"❌ Webhook request failed with status {response.status_code}")
            logging.error(f"Response: {response.text}")
            return False

    except Exception as e:
        logging.error(f"❌ Error sending to webhook: {e}")
        return False

def send_s3_logs_to_webhook(yaml_file_path: str, webhook_url: str, webhook_secret: str, 
                           compromise_datetime: str, panther_compromise_datetime: str = None):
    """
    Send S3 Server Access logs from a YAML file to Panther webhook endpoint.
    """
    with open(yaml_file_path, 'r') as file:
        data = yaml.safe_load(file)
    logs = data.get('Logs', [])
    if not logs:
        logging.warning(f"No logs found in {yaml_file_path}")
        return False

    compromise_dt = datetime.fromisoformat(compromise_datetime.replace('Z', '+00:00'))
    if panther_compromise_datetime:
        panther_dt = datetime.fromisoformat(panther_compromise_datetime.replace('Z', '+00:00'))
    else:
        panther_dt = datetime.now(timezone.utc)
    time_shift = panther_dt - compromise_dt

    shifted_logs = []
    timestamp_pattern = r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} \+0000)\]'
    for log in logs:
        def shift_timestamp(match):
            timestamp_str = match.group(1)
            original_time = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')
            shifted_time = original_time + time_shift
            return f"[{shifted_time.strftime('%d/%b/%Y:%H:%M:%S +0000')}]"
        shifted_log = re.sub(timestamp_pattern, shift_timestamp, log)
        shifted_logs.append(shifted_log)

    headers = {
        'Content-Type': 'application/json',
        'okta-header': webhook_secret,
        'User-Agent': 'Panther-Test-Scenario/1.0'
    }

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
    except Exception as e:
        logging.error(f"❌ Error sending to webhook: {e}")
        return False