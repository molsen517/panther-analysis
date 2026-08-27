#!/usr/bin/env python3
"""
Configuration file for AWS test scenarios.
Update these values to match your AWS dev account and Panther setup.
"""

# AWS Configuration
AWS_ACCOUNT_ID = "160893303461"  # Your AWS account ID
AWS_REGION = "us-east-1"  # Your preferred region

# Panther Configuration
PANTHER_BUCKET_NAME = "aws-cloudtrail-logs-160893303461-6604ba76"  # Your Panther S3 bucket name for CloudTrail
PANTHER_VPC_BUCKET_NAME = "aws-vpc-flow-logs-160893303461"  # Your Panther S3 bucket name for VPC Flow logs
PANTHER_VPC_REGION = "us-east-2"  # Region for VPC Flow logs bucket
PANTHER_S3_BUCKET_NAME = "s3aws-server-access-logs"  # Your Panther S3 bucket name for S3 Server Access logs
PANTHER_S3_REGION = "us-east-1"  # Region for S3 Server Access logs bucket

# Panther Webhook Configuration
# Okta logs
PANTHER_OKTA_WEBHOOK_URL = "https://logs.panther-partner-team.runpanther.net/http/bc91a3eb-7192-4cbe-91c7-fda88e62e023"
PANTHER_OKTA_WEBHOOK_SECRET = "46c42ea1-2451-4285-8e12-c2ae04920286"

# S3 Server Access logs
PANTHER_S3_WEBHOOK_URL = "https://logs.panther-partner-team.runpanther.net/http/4f5f1ddc-360b-4c5e-9332-df183f45d349"
PANTHER_S3_WEBHOOK_SECRET = "a67a25d3-cca4-4cbc-ab5e-b785e0cc3b6b"

# VPC Flow logs
PANTHER_VPC_WEBHOOK_URL = "https://logs.panther-partner-team.runpanther.net/http/a2b5fa32-f82c-46f1-8e38-0532ce414fbc"
PANTHER_VPC_WEBHOOK_SECRET = "b194419d-f1ba-45fa-b48b-e5ccd503d337"

# AWS Cloudtrail logs
PANTHER_CLOUDTRAIL_WEBHOOK_URL = "https://logs.panther-partner-team.runpanther.net/http/814dce5d-c3b9-42e9-8626-daf714e60221"
PANTHER_CLOUDTRAIL_WEBHOOK_SECRET = "4d35e845-8d97-4584-be82-2095d56d67d3"

# 1Password logs
PANTHER_1PASSWORD_WEBHOOK_URL = "https://logs.panther-partner-team.runpanther.net/http/ecc5e563-8bb1-42d1-93ea-c2be008ebba6"
PANTHER_1PASSWORD_WEBHOOK_SECRET = "bb5daf57-66a7-4b71-9d6b-d1d08197b5f6"

# Test Scenario Configuration
COMPROMISE_DATETIME = "2025-09-15T18:00:00+00:00"  # Updated to September 2025
PANTHER_COMPROMISE_DATETIME = None  # Will default to current time if None

# File paths
SEND_DATA_SCRIPT = "send_data.py"
TEST_SCENARIOS_DIR = "compromised-root-creds"