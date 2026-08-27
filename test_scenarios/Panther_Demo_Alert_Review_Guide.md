# Panther Demo: Compromised Root Credentials Attack Scenario
## Recommended Alert Review Order for Customer Demonstrations

---

## 🎯 **Attack Overview**
**Scenario**: Compromised AWS Root Credentials Attack  
**Timeline**: September 15, 2025  
**Duration**: 5-day attack progression  
**Impact**: Data exfiltration, privilege escalation, persistent access

---

## 📋 **Demo Script: Recommended Alert Review Order**

### **Phase 1: Set the Context (5 minutes)**
> *"Let me show you how Panther detected a sophisticated attack that unfolded over several days in September 2025."*

#### **1. Start with the Victim Baseline**
**Alert**: `AWS.CloudTrail.NormalConsoleActivity` or `Okta.SystemLog.SuccessfulLogin`
- **Purpose**: Establish normal user behavior
- **Key Points**:
  - Show legitimate user (Tracey Stone) logging in from San Francisco
  - Demonstrate normal AWS console activity
  - Set baseline for comparison

**Demo Script**:
> *"Here we see normal, legitimate activity from our employee Tracey Stone logging into AWS from San Francisco. This establishes our baseline of normal behavior."*

---

### **Phase 2: Show the Reconnaissance (3 minutes)**
> *"Now let's see how the attacker began their reconnaissance."*

#### **2. Failed Login Attempts**
**Alert**: `Okta.SystemLog.MultipleFailedLogins` or `Okta.SystemLog.SuspiciousLoginLocation`
- **Purpose**: Show attacker reconnaissance
- **Key Points**:
  - Multiple failed login attempts from Romania (92.55.146.245)
  - Attempting to use similar username (tracy_stone vs tracey_stone)
  - Geographic anomaly detection

**Demo Script**:
> *"Here's where the attack begins. We see multiple failed login attempts from Romania, trying to use a username very similar to our legitimate employee. This is classic reconnaissance behavior."*

---

### **Phase 3: The Compromise (5 minutes)**
> *"The attacker eventually succeeded in compromising our AWS root credentials."*

#### **3. Successful Compromise**
**Alert**: `AWS.CloudTrail.RootAccountUsage` or `AWS.CloudTrail.SuspiciousConsoleLogin`
- **Purpose**: Show the moment of compromise
- **Key Points**:
  - Successful login from attacker IP (92.55.146.245)
  - Root account usage (high privilege)
  - Geographic anomaly (Romania vs San Francisco)

**Demo Script**:
> *"This is the critical moment - the attacker successfully logged into our AWS root account from Romania. Notice the geographic anomaly and the use of root credentials."*

---

### **Phase 4: Privilege Escalation & Persistence (7 minutes)**
> *"Once inside, the attacker immediately began establishing persistence and escalating privileges."*

#### **4. Privilege Escalation**
**Alert**: `AWS.CloudTrail.PrivilegeEscalation` or `AWS.CloudTrail.SuspiciousAPI`
- **Purpose**: Show attacker establishing persistence
- **Key Points**:
  - Creating new IAM user (tracy_stone)
  - Attaching multiple high-privilege policies
  - Creating access keys for persistence
  - Attempting to stop CloudTrail logging

**Demo Script**:
> *"The attacker immediately began privilege escalation. They created a new IAM user, attached multiple high-privilege policies including EC2, S3, and IAM full access, and created access keys for persistent access. They also tried to stop CloudTrail logging to hide their tracks."*

---

### **Phase 5: Infrastructure Abuse (5 minutes)**
> *"The attacker then spun up infrastructure to support their attack."*

#### **5. Resource Creation**
**Alert**: `AWS.CloudTrail.UnusualServiceUsage` or `AWS.CloudTrail.EC2InstanceCreation`
- **Purpose**: Show attacker creating attack infrastructure
- **Key Points**:
  - Launching expensive EC2 instances (p2.8xlarge)
  - Using compromised access keys
  - Establishing attack infrastructure

**Demo Script**:
> *"The attacker launched expensive EC2 instances using the compromised credentials. This shows they're establishing infrastructure for their attack operations."*

---

### **Phase 6: Data Exfiltration (5 minutes)**
> *"Now let's see the data theft in action."*

#### **6. Data Exfiltration**
**Alert**: `AWS.S3ServerAccess.LargeDataDownload` or `AWS.S3ServerAccess.SuspiciousAccessPattern`
- **Purpose**: Show data theft
- **Key Points**:
  - Accessing customer data bucket (acme.customerdata-prod)
  - Downloading multiple PDF files (id-01.pdf, id-02.pdf, id-03.pdf)
  - Large data transfers

**Demo Script**:
> *"Here's the data exfiltration. The attacker accessed our customer data bucket and downloaded multiple PDF files containing sensitive customer information. This represents the actual data theft."*

---

### **Phase 7: Network Activity & C2 (5 minutes)**
> *"Finally, let's see the network communication and command & control activity."*

#### **7. Command & Control Communication**
**Alert**: `AWS.VPCFlow.SuspiciousOutboundTraffic` or `AWS.VPCFlow.C2Communication`
- **Purpose**: Show C2 and data exfiltration over network
- **Key Points**:
  - SSH connections to external IP (92.55.146.245:22)
  - Large data transfers to external IPs
  - S3 data transfer patterns
  - Network-based evidence of compromise

**Demo Script**:
> *"The network logs show the complete picture. We see SSH connections to the attacker's command & control server, large data transfers, and the network evidence of data exfiltration. This completes the attack chain."*

---

## 🎭 **Complete Attack Story Narrative**

> **"The Compromised Root Credentials Attack"**
> 
> 1. **Reconnaissance** (Sept 10-11): Attacker attempts multiple failed logins from Romania
> 2. **Compromise** (Sept 15): Attacker successfully logs into AWS root account
> 3. **Privilege Escalation** (Sept 15): Creates persistent access and high-privilege user
> 4. **Infrastructure Abuse** (Sept 15): Launches expensive EC2 instances for attack operations
> 5. **Data Exfiltration** (Sept 15): Downloads customer data from S3 buckets
> 6. **C2 Communication** (Sept 15): Establishes command & control and transfers stolen data

---

## 📊 **Demo Timing & Flow**

| **Phase** | **Duration** | **Key Message** | **Customer Takeaway** |
|-----------|--------------|-----------------|----------------------|
| **Context** | 5 min | Normal baseline activity | Panther establishes baselines |
| **Reconnaissance** | 3 min | Early threat detection | Panther detects reconnaissance |
| **Compromise** | 5 min | Critical security event | Panther alerts on compromise |
| **Privilege Escalation** | 7 min | Attack progression | Panther tracks attack evolution |
| **Infrastructure Abuse** | 5 min | Resource abuse detection | Panther detects resource misuse |
| **Data Exfiltration** | 5 min | Data theft evidence | Panther shows data loss |
| **Network Activity** | 5 min | Complete attack picture | Panther provides full context |

**Total Demo Time**: ~35 minutes

---

## 🎯 **Key Demo Messages**

### **1. Comprehensive Coverage**
> *"Panther detected this attack across multiple data sources - Okta, CloudTrail, S3, and VPC Flow logs - providing complete visibility."*

### **2. Timeline Correlation**
> *"Notice how Panther correlated events across the 5-day timeline, showing the complete attack progression from reconnaissance to data exfiltration."*

### **3. Real-time Detection**
> *"Each of these alerts fired in real-time as the attack unfolded, allowing for immediate response."*

### **4. Cross-Service Correlation**
> *"Panther automatically correlated the Okta reconnaissance with the AWS compromise and subsequent activities."*

---

## 🔧 **Technical Setup Notes**

### **Prerequisites**
- All test data sent to Panther with September 2025 timestamps
- Okta logs via webhook
- AWS logs via S3 buckets
- Proper log source configuration

### **Alert Configuration**
- Ensure all relevant Panther rules are enabled
- Verify alert severity levels (Critical/High for key events)
- Check alert correlation settings

### **Demo Environment**
- Use Panther's alert timeline view
- Show alert details and raw log data
- Demonstrate alert investigation workflow

---

## 📝 **Post-Demo Discussion Points**

### **Response Capabilities**
- How would you respond to each alert?
- What automated responses could be configured?
- How would you investigate further?

### **Prevention Measures**
- What controls could prevent this attack?
- How would MFA have helped?
- What monitoring improvements are needed?

### **Business Impact**
- What's the business impact of this attack?
- How much data was potentially compromised?
- What are the compliance implications?

---

*This guide provides a structured approach to demonstrating Panther's capabilities using the compromised root credentials attack scenario. The recommended order tells a compelling story while showcasing Panther's comprehensive detection and correlation capabilities.*
