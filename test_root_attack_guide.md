# Complete Guide: Testing Compromised Root Credentials Attack

## 🎯 **What You Have:**

The YAML file `test_scenarios/compromised-root-creds/attacker_cloudtrail.yml` contains **sample CloudTrail logs** that represent a compromised root credentials attack. This is **NOT executable code** - it's test data to validate your detection rules.

## 🚀 **How to Use This Test Scenario:**

### **Option 1: Test Your Panther Rules (Recommended)**

Test if your existing rules would catch this attack:

```bash
# Test root activity rule
pipenv run pat test --filter RuleID=AWS.Root.Activity

# Test root console login rule  
pipenv run pat test --filter RuleID=AWS.Console.Root.Login

# Test root access key creation rule
pipenv run pat test --filter RuleID=AWS.Root.AccessKey.Created
```

### **Option 2: Manual Simulation in Test AWS Account**

**⚠️ ONLY IN TEST/DEVELOPMENT ACCOUNTS!**

1. **Login to AWS Console as root** (3 failed attempts, then success)
2. **Create root access key**: `aws iam create-access-key --user-name root`
3. **Create new IAM user**: `aws iam create-user --user-name tracy_stone`
4. **Grant excessive permissions**:
   ```bash
   aws iam attach-user-policy --user-name tracy_stone --policy-arn arn:aws:iam::aws:policy/AmazonEC2FullAccess
   aws iam attach-user-policy --user-name tracy_stone --policy-arn arn:aws:iam::aws:policy/IAMFullAccess
   ```
5. **Create access key for new user**: `aws iam create-access-key --user-name tracy_stone`
6. **Launch expensive EC2 instance**: `aws ec2 run-instances --instance-type p2.8xlarge ...`

### **Option 3: Use AWS CLI Script**

Create a script to automate the simulation:

```bash
#!/bin/bash
# simulate_root_attack.sh

echo "🚨 Simulating compromised root credentials attack..."

# Step 1: Create root access key (HIGH RISK!)
echo "Creating root access key..."
aws iam create-access-key --user-name root

# Step 2: Create suspicious IAM user
echo "Creating suspicious IAM user..."
aws iam create-user --user-name tracy_stone

# Step 3: Grant excessive permissions
echo "Granting excessive permissions..."
aws iam attach-user-policy --user-name tracy_stone --policy-arn arn:aws:iam::aws:policy/AmazonEC2FullAccess
aws iam attach-user-policy --user-name tracy_stone --policy-arn arn:aws:iam::aws:policy/IAMFullAccess

# Step 4: Create access key for new user
echo "Creating access key for new user..."
aws iam create-access-key --user-name tracy_stone

echo "✅ Attack simulation complete! Check your Panther alerts."
```

## 🔍 **Expected Panther Rule Triggers:**

Based on the attack sequence, these rules should trigger:

1. **AWS.Root.Activity** - Any root user activity
2. **AWS.Root.AccessKey.Created** - Root access key creation  
3. **AWS.Console.Root.Login** - Root console login
4. **AWS.IAM.User.Created** - New user creation (if rule exists)
5. **AWS.EC2.Instance.Launched** - Expensive instance launch

## 🧹 **Cleanup After Testing:**

```bash
# Terminate EC2 instances
aws ec2 terminate-instances --instance-ids $(aws ec2 describe-instances --query 'Reservations[*].Instances[*].InstanceId' --output text)

# Delete IAM user and access keys
aws iam delete-access-key --user-name tracy_stone --access-key-id $(aws iam list-access-keys --user-name tracy_stone --query 'AccessKeyMetadata[0].AccessKeyId' --output text)
aws iam delete-user --user-name tracy_stone

# Delete root access key (if created)
aws iam delete-access-key --user-name root --access-key-id $(aws iam list-access-keys --user-name root --query 'AccessKeyMetadata[0].AccessKeyId' --output text)
```

## 📊 **Monitoring the Attack:**

1. **Check Panther Console** for alerts
2. **Monitor CloudTrail** for the events
3. **Check AWS Cost Explorer** for unexpected charges
4. **Review IAM Access Analyzer** for policy violations

## 🎯 **Key Indicators to Look For:**

- ✅ Root user activity (should be rare)
- ✅ Root access key creation (high risk)
- ✅ New IAM user with excessive permissions
- ✅ Expensive resource launches (p2.8xlarge instances)
- ✅ Unusual IP addresses or locations
- ✅ Rapid sequence of privilege escalation actions

## 🔒 **Security Best Practices:**

1. **Never use root user** for daily operations
2. **Enable MFA** on root account
3. **Monitor root activity** closely
4. **Use IAM users/roles** instead of root
5. **Implement least privilege** access
6. **Monitor for privilege escalation** patterns

## 📝 **Next Steps:**

1. Run the Panther rule tests to see if they catch the attack
2. If rules don't trigger, consider creating new detection rules
3. Test the manual simulation in a safe test environment
4. Document your findings and improve your security posture

