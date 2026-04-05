# Enterprise SOC Lab: SMB Brute Force Detection & SIEM Rule Tuning 🛡️🔍

## 📖 Objective
The goal of this project was to simulate a modern SMB Brute Force attack against a Windows 10 target within a localized Active Directory-style environment, analyze the default SIEM behavior (Wazuh), and engineer a custom detection rule to accurately identify the threat. 

Crucially, this project highlights a common **Detection Engineering & Troubleshooting (RCA)** scenario: resolving XML syntax errors and Rule ID conflicts that cause SIEM analysis engines to fail silently.

## 🛠️ Tools & Environment
* **SIEM:** Wazuh (Manager & Agent)
* **Target:** Windows 10 (Custom VIP User: `CEO_TEST`)
* **Attacker:** Kali Linux
* **Offensive Tool:** CrackMapExec (NetExec)
* **Log Source:** Windows Event Logs (Event ID: 4625)

---

## 🔴 Phase 1: The Attack (Red Team Operation)
To simulate a targeted attack, a localized user account (`CEO_TEST`) was created on the Windows 10 machine. Instead of using legacy tools like Hydra, the modern post-exploitation tool **CrackMapExec** was utilized to perform an SMB brute-force attack using a custom wordlist.

```bash
crackmapexec smb 10.0.2.4 -u CEO_TEST -p passwords.txt
```
The tool successfully brute-forced the SMB service and retrieved the correct password, simulating a successful initial access vector.

![crack_map](https://github.com/user-attachments/assets/c3b791a3-2d9d-4667-958a-748935bbdd8e)

## 🔵 Phase 2: The SIEM Blind Spot (Blue Team Analysis)
The attack successfully generated multiple (`Event ID 4625 (Logon Failure)`) logs. However, Wazuh's default rule (`Rule ID: 60122`) only categorized these as **Level 5 (Low/Medium)** alerts.

In a real-world enterprise environment, thousands of Level 5 alerts generate alert fatigue. A sustained brute-force attack should trigger a critical correlation alert, but it did not.

![log_1](https://github.com/user-attachments/assets/03f64932-1fa2-48a6-8848-5de914b984f5)

## ⚙️ Phase 3: Troubleshooting & Root Cause Analysis (RCA)
I attempted to write a custom correlation rule to trigger a **Level 12 (Critical)** alert if 5 failed logons occurred within 2 minutes. However, the rule failed to execute.

**Root Cause Analysis:**
Upon investigating the SIEM backend architecture, I discovered catastrophic issues within the (`local_rules.xml`) file:

* **Duplicate Rule IDs:** Multiple custom rules were sharing the same IDs (e.g., (`100001, 100002`)), causing the (`wazuh-analysisd`) engine to crash logically.

* **Broken XML Syntax:** Missing closing tags (`</rule>`) from previous configurations corrupted the entire file.

Because of these structural failures, the SIEM engine rejected the custom rules file entirely, leaving the system blind to the new detection logic. I successfully sanitized the XML file, reassigned unique IDs (100001 through 100012), and restarted the manager.

![local_rules](https://github.com/user-attachments/assets/40c42700-c0aa-4b14-98ea-7df6db600d8e)

## 🏗️ Phase 4: Detection Engineering (Custom Rule)
To ensure the brute-force attack is caught accurately, I engineered the following rule. Instead of matching by Source IP (which attackers can spoof or change via proxies), I mapped the correlation to the Target User using `<same_field>win.eventdata.targetUserName</same_field>.`
``` bash
<rule id="100012" level="12" frequency="3" timeframe="120">
    <if_matched_sid>60122</if_matched_sid>
    <same_field>win.eventdata.targetUserName</same_field>
    <description>CRITICAL: Brute Force Attack Detected against user: $(win.eventdata.targetUserName)</description>
    <mitre>
        <id>T1110</id>
    </mitre>
</rule>
```

## 🏆 Phase 5: Validation & Victory
After the SIEM engine was restored and the optimized rule was deployed, the brute-force attack was re-launched. The SIEM successfully correlated the logs and triggered a Level 12 Critical Alert, dynamically extracting the targeted user (`CEO_TEST`) into the alert description.

![100012_rules](https://github.com/user-attachments/assets/65d265a2-ac69-4aed-a70b-9be5afc2cf1b)


## 💡 Key Takeaways
* **Detection Engineering** is not just about writing rules; it is about understanding the underlying JSON/XML parsing engines.

* **Alert Fatigue** must be actively managed by escalating repetitive low-level logs into high-fidelity correlation alerts.

* **System Stability** dictates visibility. A broken configuration file is just as dangerous as a sophisticated threat actor.

### **Update:** A universal Sigma Rule (`brute_force_target_user.yml`) has been added to this repository for cross-SIEM compatibility (Splunk, QRadar, Sentinel).

---

# Wazuh SOC Lab Use Cases: Real-Time Threat Detection & Automated Response (SOAR)

## 📖 Objective
This repository is a comprehensive showcase of end-to-end Security Operations Center (SOC) simulations engineered within a localized, custom-built lab environment. The primary focus is to demonstrate practical expertise in bridging the gap between technical threat detection and corporate risk management.

Key competencies demonstrated include:
* **Detection Engineering** (Sysmon, Wazuh FIM)
* **Rule Tuning & Correlation** (Custom XML, YAML/Sigma)
* **Automated Incident Response** (SOAR/Active Response)
* **Root Cause Analysis (RCA)** during implementation

---

## 🛠️ Environment Architecture
* **SIEM:** Wazuh (Manager & Agent)
* **Target:** Windows 10 (Endpoints)
* **Logs:** Windows Security Events, Sysmon, File Integrity Monitoring (FIM)

---

## 🦠 Use Case 1: Real-Time Ransomware Mitigation (SOAR)

### 🚨 Objective
Detect a localized ransomware simulation and automatically execute a "Kill Switch" to terminate the malicious process before significant data encryption occurs.

### 🔴 Phase 1: Attack Simulation (Red Team)
A custom ransomware simulation (`Vengam Ransomware`) was executed. This PowerShell-based payload was obfuscated and hidden within a Batch (`.bat`) file to impersonate a legitimate "Emergency Payment Invoice".

### 🔵 Phase 2: Detection Engineering (Blue Team)
Wazuh's File Integrity Monitoring (FIM) was configured for real-time monitoring of sensitive directories (`C:\Users\Public\Financial_Statements`). A custom correlation rule (**Rule ID: 100013, Level 12**) was engineered to detect specific ransomware artifacts, such as malicious file extensions (`.vengam_locked`) and ransom notes.

![rule_id100013](https://github.com/user-attachments/assets/c6bc7895-fb50-4de4-9e3d-51a81f6afb51)

Crucially, the rule was set to **Real-Time** mode to ensure instant alerting, a fundamental component of effective ransomware defense.

![realtime](https://github.com/user-attachments/assets/dac7d9cc-662b-4da6-b335-642078ed62e6)

### 🛡️ Phase 3: Automated Response (SOAR / Active Response)
To minimize the Mean Time to Remediate (MTTR), a custom **Active Response** command was configured. Upon firing Rule 100013, the Wazuh Manager immediately triggered a remote execution of `kill_ransomware.cmd` on the target Windows 10 asset, which forcibly terminated the malicious PowerShell process and dropped a defensive log.

![kill_ransomware](https://github.com/user-attachments/assets/c938697a-3e95-48e1-badb-92df79d947ca)

### 🏆 Results & RCA
The operaton was a complete success. The ransomware was neutralized instantly. This was validated by the creation of the `SOC_DEFENSE_LOG.txt` file within the protected directory, which prevented further data encryption. During implementation, a silent failure was resolved by troubleshooting XML syntax errors (`rules_id` vs `rule_id`) and configuring correct file extensions in the Manager backend, highlighting advanced systems engineering and Root Cause Analysis (RCA) skills.

![ransom_sonuc](https://github.com/user-attachments/assets/5e0265f0-c1e1-4694-ac2c-086ab5cdb725)

---

## 🛡️ Use Case 2: Enterprise Brute Force Detection (Previous Project)

### 🚨 Objective
Detect and correlate a targeted SMB brute force attack against a custom administrative user (`CEO_TEST`) across the network.

### 🔴 Phase 1: Attack Simulation
A network brute force attack was simulated using **CrackMapExec**, utilizing a custom wordlist to target the target user's SMB service.

### 🔵 Phase 2: Correlation and Sigma Rule Tuning
Wazuh's default low-level alerts were engineered into a **Level 12 Criticalcorrelation alert** using unique XML rule tuning (`<same_field>`). A duplicate Rule ID conflict was identified and resolved during this phase.

Furthermore, a universal **Sigma (YAML)** rule was engineered to map this Use Case for cross-SIEM compatibility (Splunk, QRadar, Sentinel), demonstrating expertise in eviscerating alert fatigue and implementing enterprise-grade threat detection strategies.

