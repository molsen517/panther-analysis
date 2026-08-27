# Panther AWS Compromised Credentials Test Scenarios

This repository contains a suite of test scenarios for simulating compromised AWS credentials and related security events. The goal is to validate log ingestion, detection, and alerting in Panther using both webhook and S3 bucket log sources.

---

## 🏗️ **Setup Overview**

- **AWS Account:**  
  All test scenarios are designed for AWS account `160893303461` (update in `config.py` if needed).

- **Panther Log Sources:**  
  - **CloudTrail:** S3 bucket (`aws-cloudtrail-logs-160893303461-6604ba76`)
  - **VPC Flow Logs:** S3 bucket (`aws-vpc-flow-logs-160893303461`)
  - **S3 Server Access Logs:** S3 bucket (`s3aws-server-access-logs`)
  - **Okta, CloudTrail, VPC, S3:** Webhook endpoints (see `config.py` for URLs/secrets)

- **Log Delivery:**  
  - **Webhook-based sources:** Logs are sent via HTTP POST to Panther webhooks.
  - **S3-based sources:** Logs are uploaded as `.log` files to the appropriate S3 bucket.

- **Configuration:**  
  All scenario and environment settings are in [`test_scenarios/config.py`](test_scenarios/config.py).

---

## 🚦 **How to Run Scenarios**

1. **Install dependencies:**  
   ```sh
   pip install -r requirements.txt
   ```

2. **Configure AWS credentials:**  
   Ensure your AWS CLI or environment is configured to allow S3 uploads.

3. **Update `config.py`:**  
   - Set your AWS account ID, region, Panther bucket names, and webhook URLs/secrets as needed.

4. **Run all or selected scenarios:**  
   ```sh
   cd test_scenarios
   python run_all_scenarios.py
   ```
   - You will be prompted to enter a range or list of scenarios (e.g. `1,3,5` or `2-4`). Leave blank to run all.

---

## 🧪 **Test Scenarios**

| #  | Script Name                      | Description                                                                 | Log Source Type | Log File(s) Used                          |
|----|----------------------------------|-----------------------------------------------------------------------------|-----------------|--------------------------------------------|
| 1  | 01_send_victim_okta.py           | Sends Okta logs for legitimate user activity                                | Webhook         | victim_okta.yml                            |
| 2  | 02_send_victim_cloudtrail.py      | Sends CloudTrail logs for legitimate AWS console activity                   | Webhook         | victim_cloudtrail.yml                      |
| 3  | 03_send_attacker_okta.py         | Sends Okta logs for attacker activity (e.g. session hijack)                 | Webhook         | attacker_okta.yml                          |
| 4  | 04_send_attacker_cloudtrail.py    | Sends CloudTrail logs for attacker AWS activity                             | Webhook         | attacker_cloudtrail.yml                    |
| 5  | 05_send_attacker_s3_access.py     | Uploads S3 access logs showing data exfiltration to S3 bucket               | S3 Bucket       | attacker_s3_access_complete.yml/.log        |
| 6  | 06_send_attacker_vpc.py           | Uploads VPC flow logs showing C2/data exfiltration to S3 bucket             | S3 Bucket       | attacker_vpc_panther_format.yml/.log        |
| 7  | 07_send_session_takeover_okta.py | Sends Okta logs for session takeover scenario                               | Webhook         | session_takeover_okta_legit.yml            |
| 8  | 08_send_access_key_compromise.py  | Sends CloudTrail logs for access key compromise (root or privileged user)   | Webhook         | 08_access_key_normal.yml, 08_access_key_suspicious.yml |

---

## 📂 **File Structure**

```
test_scenarios/
├── config.py
├── run_all_scenarios.py
├── webhook_sender.py
├── 01_send_victim_okta.py
├── 02_send_victim_cloudtrail.py
├── ...
├── compromised-root-creds/
│   ├── victim_okta.yml
│   ├── victim_cloudtrail.yml
│   ├── attacker_okta.yml
│   ├── attacker_cloudtrail.yml
│   ├── attacker_s3_access_complete.yml
│   ├── attacker_vpc_panther_format.yml
│   └── ...
```

---

## 📝 **Notes**

- **Webhook scenarios** use `webhook_sender.py` to POST logs to Panther.
- **S3 scenarios** convert YAML to `.log` and upload to S3 using `boto3`.
- **No Panther API credentials are required** for these scenarios; only AWS credentials for S3 uploads and Panther webhook secrets for HTTP POSTs.
- **You can run a subset of scenarios** by entering a range or list when prompted by `run_all_scenarios.py`.

---

## 👥 **Sharing with Teammates**

- Share this README and the repo.
- Make sure teammates update `config.py` with their own Panther and AWS details if needed.
- Ensure AWS credentials are set up for S3 uploads.