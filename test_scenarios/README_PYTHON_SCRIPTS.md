# Python Scripts for Compromised Root Credentials Test Scenario

This directory contains individual Python scripts to execute the compromised root credentials test scenario against your AWS dev account. Each script sends specific log data to your Panther instance.

## Quick Start

1. **Update Configuration**: Edit `config.py` with your AWS account details:
   ```python
   AWS_ACCOUNT_ID = "123456789012"  # Your AWS account ID
   PANTHER_BUCKET_NAME = "my-panther-bucket"  # Your Panther S3 bucket
   AWS_REGION = "us-east-1"  # Your preferred region
   
   # Panther Webhook Configuration (for Okta logs)
   PANTHER_WEBHOOK_URL = "https://logs.panther-partner-team.runpanther.net/http/bc91a3eb-7192-4cbe-91c7-fda88e62e023"
   PANTHER_WEBHOOK_SECRET = "46c42ea1-2451-4285-8e12-c2ae04920286"
   ```

2. **Test Webhook Connection** (for Okta logs): Verify your webhook is working:
   ```bash
   python test_webhook_connection.py
   ```

3. **Run All Scenarios**: Execute the master script:
   ```bash
   python run_all_scenarios.py
   ```

4. **Or Run Individual Scripts**: Execute scripts one by one:
   ```bash
   python 01_send_victim_okta.py
   python 02_send_victim_cloudtrail.py
   python 03_send_attacker_okta.py
   python 04_send_attacker_cloudtrail.py
   python 05_send_attacker_s3_access.py
   python 06_send_attacker_vpc.py
   ```

## Scripts Overview

| Script | Description | Log Type | Delivery Method | Purpose |
|--------|-------------|----------|----------------|---------|
| `01_send_victim_okta.py` | Legitimate user login | Okta.SystemLog | **Webhook** | Shows normal user activity |
| `02_send_victim_cloudtrail.py` | Legitimate AWS console access | AWS.CloudTrail | S3 Bucket | Shows normal AWS usage |
| `03_send_attacker_okta.py` | Failed login attempts | Okta.SystemLog | **Webhook** | Shows reconnaissance attempts |
| `04_send_attacker_cloudtrail.py` | Malicious AWS activity | AWS.CloudTrail | S3 Bucket | Shows compromise and privilege escalation |
| `05_send_attacker_s3_access.py` | Data exfiltration | AWS.S3ServerAccess | S3 Bucket | Shows data theft |
| `06_send_attacker_vpc.py` | Network activity | AWS.VPCFlow | S3 Bucket | Shows C2 and data exfiltration |

## Timeline

The test scenario follows this timeline:

- **10/26-10/27/2020**: Failed logins from attacker (Okta)
- **10/27/2020**: Legitimate logins from team (CloudTrail)
- **10/30/2020**: Failed logins from attacker (CloudTrail)
- **11/01/2020**: Successful login from attacker (CloudTrail)
- **11/01/2020**: Attacker creates user and access keys (CloudTrail)
- **11/01/2020**: Attacker launches EC2, accesses S3, stops CloudTrail (CloudTrail)
- **11/01/2020**: Data exfiltration (S3 Access Logs, VPC Flow)

## Key Actors

- **Legitimate User**: Tracey Stone (tracey.stone@acme.io)
- **Attacker**: tracy_stone (no 'e') - impersonating the legitimate user
- **Legitimate IP**: 71.253.251.71 (San Francisco)
- **Attacker IP**: 92.55.146.245 (Romania)
- **Compromised Account**: 493859302102
- **Malicious Access Key**: AKIASWJJJ66ZZZII4IYY

## Prerequisites

1. **AWS Credentials**: Ensure your AWS credentials are configured (via AWS CLI, environment variables, or IAM role)
2. **Panther Setup**: 
   - Your Panther instance should be configured to ingest from the specified S3 bucket (for AWS logs)
   - Your Panther webhook should be configured for Okta logs
3. **Python Dependencies**: The scripts require:
   - boto3 (for S3 uploads)
   - pyyaml (for YAML parsing)
   - requests (for webhook calls)

## Configuration Options

Edit `config.py` to customize:

- `AWS_ACCOUNT_ID`: Your AWS account ID
- `AWS_REGION`: AWS region for your Panther bucket
- `PANTHER_BUCKET_NAME`: S3 bucket name configured in Panther
- `PANTHER_WEBHOOK_URL`: Panther webhook URL for Okta logs
- `PANTHER_WEBHOOK_SECRET`: Shared secret for webhook authentication
- `COMPROMISE_DATETIME`: Original compromise date (default: 2020-11-01T18:00:00+00:00)
- `PANTHER_COMPROMISE_DATETIME`: When to show the compromise in Panther (default: current time)

## Troubleshooting

### Common Issues

1. **"send_data.py not found"**: Make sure you're running scripts from the `test_scenarios` directory
2. **AWS credentials error**: Verify your AWS credentials are configured correctly
3. **S3 bucket access denied**: Ensure your AWS credentials have write access to the Panther bucket
4. **Import error**: Make sure you have the required Python packages installed

### Debug Mode

To see detailed output from the underlying `send_data.py` script, you can run it directly:

```bash
python send_data.py --account-id YOUR_ACCOUNT_ID --region us-east-1 --compromise-datetime '2020-11-01T18:00:00+00:00' --bucket-name YOUR_BUCKET --file compromised-root-creds/victim_okta.yml
```

## Expected Results

After running all scripts, you should see the following in your Panther console:

1. **Okta logs** showing legitimate and failed login attempts
2. **CloudTrail logs** showing normal and malicious AWS activity
3. **S3 access logs** showing data exfiltration
4. **VPC flow logs** showing network activity and C2 communication

Various Panther detection rules should trigger based on this activity, including:
- Failed login attempts from unusual locations
- Root user activity
- Privilege escalation
- Data exfiltration
- Unusual network activity

## Security Note

These scripts send test data to simulate a security incident. The data contains:
- Simulated user credentials and access keys
- Fake IP addresses and locations
- Mock AWS resource identifiers

This is test data only and should not be used in production environments.
