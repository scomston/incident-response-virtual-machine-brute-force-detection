# Brute Force Logon Attempt Detection and Incident Response Report

This repository documents the detection, investigation, and remediation of a brute force logon attempt against an Azure virtual machine using Microsoft Sentinel and Defender for Endpoint.

---

## 📌 Summary

This project demonstrates a use case for detecting brute force attacks using **Microsoft Sentinel** and **Microsoft Defender for Endpoint**, analyzing events through **Log Analytics (KQL)**, and following through with a complete **NIST 800-61 Incident Response Lifecycle**.

---

## 🔍 Detection Logic

### Sentinel Analytics Rule: Brute Force Attempt Detection

A **Scheduled Query Rule** was created in Sentinel to detect 10 or more failed logons from the same remote IP to the same VM in a 5-hour window.

**KQL Query:**
```kql
//Design a Sentinel Scheduled Query Rule within Log Analytics that will 
//discover when the same remote IP address has failed to log in to the same local 
//host (Azure VM) 10 times or more within the last 5 hours

DeviceLogonEvents
| where TimeGenerated >= ago(5h)
| where ActionType == "LogonFailed"
| summarize NumberOfFailures = count() by RemoteIP, ActionType, DeviceName
| where NumberOfFailures >=10


```

**Results:**

![image](https://github.com/user-attachments/assets/8d91cc6c-b5da-4e68-8c5d-ec5292886ec7)

**Rule Settings:**

**Frequency:** Every 4 hours

**Lookup period:** Last 5 hours

**Stop query after alert triggered:** Yes

**Entity Mappings:** RemoteIP, DeviceName

**Incident Creation:** Enabled

**Group alerts into one incident per 24 hours**


## 🛠️ Incident Response (NIST 800-61)

### 1. Preparation
- Documented roles and responsibilities.
- Tools configured: **Microsoft Sentinel**, **Defender for Endpoint**, **Log Analytics**.
- Procedures outlined for response handling.

---

### 2. Detection and Analysis
- **Incident Observed:** Multiple failed logon attempts from **13 unique IP addresses** against **11 Azure VMs**.
- **Entities Involved:**
  - **IPs:** `99.10.226.255`, `102.88.21.215`, `31.223.129.64`, etc.
  - **Hostnames:** Listed in internal notes.
 
![image](https://github.com/user-attachments/assets/d6f08b1d-f10e-4800-aeb1-3dfa1f7f8312)


#### 🔍 Validation of No Successful Breach
```kql
DeviceLogonEvents
| where RemoteIP in ("99.10.226.255", "102.88.21.215", "31.223.129.64")
| where ActionType != "LogonFailed"
```
✅ No successful logons detected from suspect IPs.

![image](https://github.com/user-attachments/assets/8bf33a80-1ed0-4948-bbe5-72f6e38b92bb)

---
### 3. Containment, Eradication, and Recovery

**Mitigation Step:** Isolated affected systems to prevent further damage. Locked down Network Security Group (NSG) to allow traffic only from local PC.

**Preventive Action:** Proposed enforcing NSG restrictions by default using Azure Policy.

**AV Scans:** Initiated via Defender (simulated for this lab).

![image](https://github.com/user-attachments/assets/c14c76f9-d822-4bc4-9feb-17c1401c910c)

---

### 4. Post-Incident Activity

Documented findings and lessons learned.

**Recommended:**

NSG hardening

Policy enforcement via Azure Policy

**Lesson Learned:** Proactive alerting + NSG baselining helps prevent successful brute force attempts.

---

### 5. Closure

Incident marked as ✅ True Positive.

Final review completed in Microsoft Sentinel.

Case closed following full investigation and documentation.

![image](https://github.com/user-attachments/assets/e96743e8-26ab-4265-9b30-da5e7ede191a)

---

### 📄 Notes and Recommendations

🛡️ Future VMs should default to NSG restrictions (no wide-open RDP from the internet).

🧠 Sentinel analytics rules can be improved with success/failure tracking logic.

🔐 Implement Multi-Factor Authentication (MFA) and Just-In-Time (JIT) access for sensitive VMs.

