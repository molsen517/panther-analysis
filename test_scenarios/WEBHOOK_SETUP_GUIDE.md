# Panther Webhook Setup Guide

This guide will help you set up webhooks for S3 Server Access logs and VPC Flow logs in Panther.

## 🎯 **Webhook Configuration Needed**

You need to create **2 new webhooks** in Panther:

### 1. **S3 Server Access Logs Webhook**
- **Data Type**: `AWS.S3ServerAccess`
- **Log Source**: S3 Server Access Logs
- **Schema**: AWS S3 Server Access Log schema
- **Purpose**: Test 5 - Data exfiltration logs

### 2. **VPC Flow Logs Webhook**
- **Data Type**: `AWS.VPCFlow`
- **Log Source**: VPC Flow Logs
- **Schema**: AWS VPC Flow Log schema
- **Purpose**: Test 6 - Network activity logs

## 📋 **Steps to Create Webhooks in Panther**

1. **Log into your Panther console**
2. **Navigate to**: Settings → Log Sources
3. **Click**: "Add Source"
4. **Select**: "HTTP Endpoint" (Webhook)
5. **Configure each webhook**:

### **S3 Webhook Configuration:**
- **Name**: `S3 Server Access Logs - Test`
- **Data Type**: `AWS.S3ServerAccess`
- **Description**: `Test webhook for S3 server access logs`
- **Authentication**: Shared Secret
- **Header Name**: `s3-header` (or similar)
- **Copy the webhook URL and secret**

### **VPC Webhook Configuration:**
- **Name**: `VPC Flow Logs - Test`
- **Data Type**: `AWS.VPCFlow`
- **Description**: `Test webhook for VPC flow logs`
- **Authentication**: Shared Secret
- **Header Name**: `vpc-header` (or similar)
- **Copy the webhook URL and secret**

## 🔧 **Update Configuration**

Once you have the webhook URLs and secrets, update `config.py`:

```python
# S3 Server Access logs
PANTHER_S3_WEBHOOK_URL = "https://logs.panther-partner-team.runpanther.net/http/YOUR_S3_WEBHOOK_ID"
PANTHER_S3_WEBHOOK_SECRET = "YOUR_S3_WEBHOOK_SECRET"

# VPC Flow logs
PANTHER_VPC_WEBHOOK_URL = "https://logs.panther-partner-team.runpanther.net/http/YOUR_VPC_WEBHOOK_ID"
PANTHER_VPC_WEBHOOK_SECRET = "YOUR_VPC_WEBHOOK_SECRET"
```

## 🧪 **Test Your Webhooks**

After setting up the webhooks, you can test them:

```bash
# Test S3 webhook
python test_s3_webhook.py

# Test VPC webhook
python test_vpc_webhook.py
```

## 📊 **Current Configuration Status**

| Log Type | Delivery Method | Status |
|----------|----------------|---------|
| **Okta.SystemLog** | Webhook | ✅ Configured |
| **AWS.CloudTrail** | S3 Bucket | ✅ Configured |
| **AWS.S3ServerAccess** | Webhook | ⏳ To be configured |
| **AWS.VPCFlow** | Webhook | ⏳ To be configured |

## 🚀 **Benefits of Using Webhooks**

1. **Easy Schema Configuration**: Set the schema directly in Panther
2. **Real-time Ingestion**: Immediate log processing
3. **No S3 Bucket Management**: No need to create/manage S3 buckets
4. **Flexible Authentication**: Use shared secrets or other auth methods
5. **Better Testing**: Easy to test with sample data

## 📝 **Next Steps**

1. Create the webhooks in Panther
2. Update `config.py` with the new URLs and secrets
3. Run the test scripts to verify connectivity
4. Execute the full test scenario

Once configured, all logs will be sent via webhooks for easy testing and schema management!
