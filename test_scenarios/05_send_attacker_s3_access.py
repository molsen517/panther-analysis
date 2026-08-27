#!/usr/bin/env python3
"""
Convert attacker S3 access logs from YAML to raw log format and upload to Panther S3 bucket.
"""

import sys
import boto3
import yaml
from datetime import datetime, timezone
from config import TEST_SCENARIOS_DIR

# S3 bucket details
BUCKET_NAME = "s3aws-server-access-logs"
S3_KEY = f"attacker_s3_access_complete_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.log"
YAML_FILE = f"{TEST_SCENARIOS_DIR}/attacker_s3_access_complete.yml"
LOG_FILE = f"{TEST_SCENARIOS_DIR}/attacker_s3_access_complete.log"

def convert_yaml_to_log(yaml_path, log_path):
    with open(yaml_path, "r") as f:
        data = yaml.safe_load(f)
    logs = data.get("Logs", [])
    with open(log_path, "w") as f:
        for line in logs:
            f.write(line + "\n")
    print(f"✅ Wrote {len(logs)} log lines to {log_path}")

def upload_to_s3(local_file, bucket, key):
    s3 = boto3.client("s3")
    s3.upload_file(local_file, bucket, key)
    print(f"✅ Uploaded {local_file} to s3://{bucket}/{key}")

def main():
    print("Converting YAML to raw log file and uploading to Panther S3 bucket...")
    print(f"YAML file: {YAML_FILE}")
    print(f"Log file: {LOG_FILE}")
    print(f"S3 Bucket: {BUCKET_NAME}")
    print(f"S3 Key: {S3_KEY}")

    convert_yaml_to_log(YAML_FILE, LOG_FILE)
    upload_to_s3(LOG_FILE, BUCKET_NAME, S3_KEY)

if __name__ == "__main__":
    main()