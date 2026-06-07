# 📚 Table of Contents

* [🧰 Platforms and Tools](#platforms-and-tools)
* [🎯 Background, Objective and Scope](#background-objective-and-scope)
* [🧠 Executive Summary](#executive-summary)
* [🔍 Summary of Findings (Flags)](#summary-of-findings-flags)
* 🧩 Key Findings by Flag (With KQL + MITRE)
  * [PHASE 1: INITIAL ACCESS & MFA FATIGUE (FLAGS 1-8)](#-flag-1-initial-compromise)
  * [PHASE 2: CLOUD ACCOUNT ACCESS (FLAGS 9-15)](#-flag-9-successful-authentication)
  * [PHASE 3: EMAIL & DATA ACCESS (FLAGS 16-22)](#-flag-16-outlook-web-access)
  * [PHASE 4: SESSION CORRELATION & INVESTIGATION (FLAGS 23-24)](#-flag-23-session-correlation)
  * [PHASE 5: DEFENSE GAPS & CONTAINMENT (FLAGS 25-28)](#-flag-25-conditional-access-status)
  * [PHASE 6: THREAT ACTOR ATTRIBUTION (FLAG 29)](#-flag-29-threat-actor-attribution)
* [🎯 MITRE ATT&CK Technique Mapping](#mitre-attck-technique-mapping)
* [☁️ Microsoft 365 Attack Chain Reconstruction](#-microsoft-365-attack-chain-reconstruction)
* [💠 Diamond Model of Intrusion Analysis](#diamond-model-of-intrusion-analysis)
* [🧾 Conclusion](#conclusion)
* [🎓 Lessons Learned](#lessons-learned)
* [🛠️ Recommendations for Remediation](#recommendations-for-remediation)

---

# 🕵️‍♀️ Threat Hunt: “Scattered Invoice - Business Email Compromise Through MFA Fatigue”

***“The attacker never deployed ransomware, executed malware, or exploited a vulnerability. Instead, they exploited trust, persistence, and a single approved MFA prompt.”***

This threat hunt examines a sophisticated Business Email Compromise (BEC) intrusion targeting a Microsoft 365 environment. Rather than relying on malware deployment or destructive payloads, the adversary leveraged previously stolen credentials, MFA fatigue techniques, and cloud-native persistence mechanisms to gain access to sensitive business communications and financial workflows.

The attack began with credentials likely harvested by infostealer malware and later acquired by a threat actor associated with Scattered Spider. Using repeated MFA push notifications, the attacker successfully convinced the user to approve a login request, granting access to the organization's Microsoft 365 tenant. Once authenticated, the adversary established persistence through malicious inbox rules designed to hide security notifications, suspicious emails, and evidence of account compromise.

Following successful access, the attacker expanded beyond email and accessed cloud-hosted resources including Microsoft OneDrive and SharePoint Online. Investigation of SignInLogs and CloudAppEvents revealed a consistent attacker session, allowing activity across authentication events, inbox rule creation, cloud application access, and business email compromise preparation to be correlated to a single Azure AD session.

This intrusion demonstrates how modern identity-focused attacks increasingly target cloud services rather than endpoints. By abusing legitimate credentials and trusted authentication workflows, threat actors can operate entirely within approved services while avoiding many traditional security controls.

This report includes:

* 📅 A phase-by-phase reconstruction of the attack lifecycle, from credential compromise through business email compromise preparation

* 🧭 MITRE ATT&CK mappings covering MFA fatigue, valid account abuse, cloud application access, defense evasion, and persistence

* 💠 A Diamond Model of Intrusion Analysis to profile adversary infrastructure, capabilities, and objectives

* 🔍 Evidence-backed explanations for all 29 flags uncovered during the investigation

* ☁️ Analysis of Microsoft 365 telemetry including SignInLogs, CloudAppEvents, inbox rule creation, and cloud application access

* 🛠️ Actionable lessons learned and remediation recommendations to strengthen identity security and cloud defenses

Scattered Invoice reinforces a critical truth for defenders: modern attacks do not always begin with malware. In cloud-first environments, a single compromised identity can provide access to email, files, collaboration platforms, and financial processes. Detecting suspicious authentication activity, enforcing strong identity controls, and rapidly revoking attacker sessions can mean the difference between a contained incident and a successful business email compromise.

---

## 🧰 Platforms and Tools

### **Telemetry / Hunting Platform**

* Microsoft Defender XDR (Advanced Hunting)
* Microsoft Entra ID (Azure AD) Sign-In Logs
* Microsoft 365 Audit Logs

### **Primary Tables Used**

* SignInLogs
* CloudAppEvents
* EmailEvents

### **Analysis Method**

* Identity and authentication correlation (SignInLogs → CloudAppEvents)
* Attacker IP pivoting across cloud services
* Session correlation using AADSessionId and SessionId
* Inbox rule analysis for persistence and defense evasion
* Email tracing for Business Email Compromise (BEC) activity
* Cloud application access investigation (Outlook, OneDrive, SharePoint)
* MITRE ATT&CK mapping and threat actor attribution

---

## 🎯 Background, Objective and Scope

### **Background**

The “Scattered Invoice” scenario simulates a Business Email Compromise (BEC) attack against a Microsoft 365 environment. The intrusion begins with credentials believed to have been harvested by an infostealer and later leveraged by a threat actor associated with Scattered Spider. After obtaining valid credentials, the attacker successfully bypasses multi-factor authentication through MFA fatigue techniques, gains access to the victim's Microsoft 365 account, establishes persistence through malicious inbox rules, and accesses cloud-hosted resources including Outlook, OneDrive, and SharePoint Online.

Rather than deploying malware or ransomware, the attacker abuses legitimate cloud services and trusted authentication workflows to conduct financial fraud while blending into normal user activity. This reflects the growing trend of identity-centric attacks that target cloud environments through valid accounts rather than software vulnerabilities.

### **Objective**

Reconstruct the attacker's behavior end-to-end, identify the techniques used to gain and maintain access, correlate authentication activity across Microsoft 365 services, map attacker actions to MITRE ATT&CK, and produce a report suitable for a SOC analyst, incident response team, or client-facing incident summary.

### **Scope**

***Systems and Services Involved (Observed)***

* Microsoft Entra ID (Azure AD) Authentication Services
* Microsoft Outlook Web Access
* Microsoft OneDrive for Business
* Microsoft SharePoint Online
* Microsoft Defender XDR Advanced Hunting

***Primary Log Sources***

* SignInLogs
* CloudAppEvents
* EmailEvents

***Key User Account Observed***

* [m.smith@lognpacific.org](mailto:m.smith@lognpacific.org) (Compromised User)

***Threat Actor Infrastructure Observed***

* Attacker IP Address: 205.147.16.190
* Threat Group Attribution: Scattered Spider

***Key Investigation Focus Areas***

* MFA Fatigue (Push Bombing)
* Malicious Inbox Rules
* Business Email Compromise (BEC)
* Cloud Application Access
* Session Correlation
* Conditional Access Analysis
* Threat Actor Attribution

---

## 🧠 Executive Summary

The attacker executed a cloud-based Business Email Compromise (BEC) campaign prioritizing ***identity compromise, persistence, and financial fraud:***

1. Obtained valid Microsoft 365 credentials likely harvested by an ***infostealer*** and subsequently leveraged by a threat actor associated with ***Scattered Spider***.

2. Successfully bypassed multi-factor authentication through ***MFA fatigue (T1621)***, convincing the victim to approve a malicious authentication request.

3. Established access to the victim account ***[m.smith@lognpacific.org](mailto:m.smith@lognpacific.org)*** from attacker IP address ***205.147.16.190*** and authenticated to multiple Microsoft 365 services.

4. Accessed Outlook Web, OneDrive for Business, and SharePoint Online to identify business communications, financial information, and organizational data.

5. Established persistence through malicious inbox rules designed to automatically forward financial emails and suppress security notifications, phishing alerts, and account compromise warnings.

6. Performed collection activities within Microsoft 365 by accessing email content, OneDrive files, and SharePoint resources while maintaining a valid Azure AD session.

7. Conducted Business Email Compromise (BEC) activity by hijacking an existing invoice conversation and sending fraudulent banking instructions to ***[j.reynolds@lognpacific.org](mailto:j.reynolds@lognpacific.org)*** under the subject ***"RE: Invoice #INV-2026-0892 - Updated Banking Details"***.

8. Evaded detection through inbox rule manipulation and benefited from a defensive control gap where ***Conditional Access policies were not applied*** to the attacker's session.

9. Maintained access through a single Azure AD session ***00225cfa-a0ff-fb46-a079-5d152fcdf72a***, allowing authentication events, mailbox activity, SharePoint access, and malicious inbox rule creation to be correlated throughout the investigation.

10. Required immediate containment through ***Revoke Sessions*** to invalidate active authentication tokens and terminate attacker access to the Microsoft 365 environment.

---

## 🔍 Summary of Findings (Flags)

* ✅ Completed in this report: Flags 1–29

| Flag | Phase                     | Category                  | Finding                                                |
| ---- | ------------------------- | ------------------------- | ------------------------------------------------------ |
| 1    | Initial Access            | Tenant Identification     | `law-cyber-range`                                      |
| 2    | Initial Access            | Compromised User          | `m.smith@lognpacific.org`                              |
| 3    | Initial Access            | Attacker IP               | `205.147.16.190`                                       |
| 4    | Initial Access            | Authentication Failure    | Error Code `50074`                                     |
| 5    | Initial Access            | MFA Fatigue               | `3` MFA failures observed                              |
| 6    | Cloud Access              | Microsoft 365 Service     | `SharePoint Online`                                    |
| 7    | Cloud Access              | Attacker Device           | `Linux`                                                |
| 8    | Cloud Access              | Attacker Browser          | `Firefox 147.0`                                        |
| 9    | Cloud Access              | First Activity            | `Application`                                          |
| 10   | Persistence               | Inbox Rule Creation       | `New-InboxRule`                                        |
| 11   | Persistence               | Financial Email Targeting | `invoice, payment, wire, transfer`                     |
| 12   | Defense Evasion           | Inbox Rule Processing     | `StopProcessingRules=True`                             |
| 13   | Collection                | OneDrive Access           | `Microsoft OneDrive for Business`                      |
| 14   | Collection                | SharePoint Access         | `SharePoint Online`                                    |
| 15   | Collection                | Data Access Pattern       | `FileAccessed` Events                                  |
| 16   | Business Email Compromise | Target Recipient          | `j.reynolds@lognpacific.org`                           |
| 17   | Business Email Compromise | Fraudulent Subject        | `RE: Invoice #INV-2026-0892 - Updated Banking Details` |
| 18   | Business Email Compromise | Email Direction           | `Intra-org`                                            |
| 19   | Business Email Compromise | Sender IP                 | `205.147.16.190`                                       |
| 20   | Session Correlation       | Azure AD Session          | `00225cfa-a0ff-fb46-a079-5d152fcdf72a`                 |
| 21   | Security Controls         | Conditional Access        | `notApplied`                                           |
| 22   | MITRE ATT&CK              | MFA Fatigue               | `T1621`                                                |
| 23   | MITRE ATT&CK              | Email Hiding Rules        | `T1564.008`                                            |
| 24   | Threat Intelligence       | Credential Source         | `Infostealer`                                          |
| 25   | Containment               | Immediate Response        | `Revoke Sessions`                                      |
| 26   | Threat Attribution        | Threat Group              | `Scattered Spider`                                     |

### Key Investigation Findings

* Successful authentication originated from attacker IP address `205.147.16.190`.
* The attacker leveraged MFA fatigue techniques to gain access to the victim account.
* Malicious inbox rules were created to forward financial communications and suppress security notifications.
* The attacker accessed Outlook Web, OneDrive for Business, and SharePoint Online.
* A fraudulent invoice email was sent internally as part of a Business Email Compromise (BEC) campaign.
* Conditional Access protections were not applied to the attacker's session.
* All observed activity was correlated through a single Azure AD session identifier.
* Tradecraft and tactics aligned closely with publicly reported Scattered Spider activity.

---

🏁 Flag 1: Microsoft 365 Tenant Identification

MITRE:
TA0007 — Discovery

Question:
What Microsoft 365 tenant was involved in the investigation?

Answer
law-cyber-range

Evidence:
<img width="766" height="341" alt="image" src="https://github.com/user-attachments/assets/c10a3a56-287d-4e6d-9901-c9b11d6cb66d" />


Why This Matters:
Identifying the tenant establishes the scope of the investigation and confirms which Microsoft 365 environment was compromised.

---

🏁 Flag 2: Compromised User Account

MITRE:
T1078.004 — Valid Accounts: Cloud Accounts

Question:
Which user account was compromised?

Answer
m.smith@lognpacific.org

Evidence:
<img width="800" height="761" alt="image" src="https://github.com/user-attachments/assets/b46166cb-2e41-4ec5-a097-f633042217a9" />


Why This Matters:
This account served as the primary victim throughout the investigation and was used by the attacker to access Microsoft 365 resources.

---

🏁 Flag 3: Attacker Location

MITRE:
T1078.004 — Valid Accounts: Cloud Accounts

Question:
What location was associated with the attacker's successful sign-in?

Answer:
Netherlands (NL)

Evidence:
<img width="784" height="283" alt="image" src="https://github.com/user-attachments/assets/8ec4bc82-3d60-48ea-bb6c-7ed0d96860b3" />


Why This Matters:
Geographic anomalies are often one of the first indicators of compromised cloud accounts. Identifying a successful sign-in from an unexpected country can help analysts rapidly scope an incident, validate suspicious authentication activity, and initiate containment actions before the attacker establishes persistence.

---

🏁 Flag 4: MFA Denial Error Code

MITRE:
T1621 — Multi-Factor Authentication Request Generation

Question:
What error code indicates that strong authentication (MFA) was required but not completed?

Answer:
50074

Evidence:
<img width="1014" height="138" alt="image" src="https://github.com/user-attachments/assets/07aae730-70bc-4b77-aaee-84b511dc0f09" />

Why This Matters:
This error indicates

---

🏁 Flag 5: MFA Fatigue Attempts Observed

MITRE:
T1621 — Multi-Factor Authentication Request Generation

Question:
How many MFA push requests did Mark deny before he approved one?

Answer:
3

Evidence:
<img width="997" height="264" alt="image" src="https://github.com/user-attachments/assets/103c01f9-6f2e-4a6f-a078-f9a43d0ce9a5" />

Why This Matters:
Multiple failed MFA attempts are consistent with MFA fatigue attacks, where an attacker repeatedly sends authentication prompts until the victim eventually approves one.

---

🏁 Flag 6: Initial Microsoft 365 Service Accessed

MITRE:
T1078.004 — Valid Accounts: Cloud Accounts

Question:
After successfully bypassing MFA, what Microsoft application did the attacker authenticate to?

Answer:
One Outlook Web

Evidence:
<img width="996" height="490" alt="image" src="https://github.com/user-attachments/assets/cc2fb8b9-1089-49e5-b42e-a092a3388c2b" />

Why This Matters:
This confirms the attacker moved beyond authentication and began interacting with Microsoft 365 resources using the compromised account.

---

🏁 Flag 7: Attacker Operating System

MITRE:
T1078.004 — Valid Accounts: Cloud Accounts

Question:
What operating system was used by the attacker during the successful authentication?

Answer:
Linux

Evidence:
<img width="996" height="240" alt="image" src="https://github.com/user-attachments/assets/96aa6ac5-3cdf-4e76-970d-ea6df3f72032" />

Why This Matters:
Identifying the attacker's operating system provides valuable context when profiling adversary infrastructure and investigating additional activity.

---

🏁 Flag 8: Attacker Browser

MITRE:
T1078.004 — Valid Accounts: Cloud Accounts

Question:
What browser and version was used by the attacker during the successful authentication?

Answer:
Firefox 147.0

Evidence:
<img width="969" height="231" alt="image" src="https://github.com/user-attachments/assets/4f5ba39f-eb59-4b09-8465-8f87d2801d7d" />

Why This Matters:
Browser artifacts assist in session correlation and help distinguish attacker activity from legitimate user behavior.

---

🏁 Flag 9: Initial Cloud Activity Type

MITRE:
T1087 – Account Discovery

Question:
What was the first recorded ActionType associated with the attacker's activity?

Answer
Application

Evidence:
<img width="1064" height="575" alt="image" src="https://github.com/user-attachments/assets/a60a079e-fd42-4256-9df9-fbc4c3378612" />

Why This Matters:
This establishes the first observable cloud activity performed after successful authentication and helps begin reconstruction of the attack timeline.

---

🏁 Flag 10: Malicious Inbox Rule Creation

MITRE:
T1114.003 — Email Collection: Email Forwarding Rule

Question:
What action indicated the attacker established persistence within the mailbox?

Answer
New-InboxRule

Evidence:
(Insert screenshot)

Why This Matters:
The creation of mailbox rules is a common Business Email Compromise persistence technique that enables attackers to monitor communications and automate malicious actions.

---

🏁 Flag 11: Financial Keyword Monitoring

MITRE:
T1114 — Email Collection

Question:
What keywords were targeted by the attacker's inbox rule?

Answer
invoice, payment, wire, transfer

Evidence:
(Insert screenshot)

Why This Matters:
These keywords reveal the attacker's objective: identifying financial communications that could be leveraged for wire fraud or invoice manipulation.

---

🏁 Flag 12: Inbox Rule Defense Evasion

MITRE:
T1564.008 — Hide Artifacts: Email Hiding Rules

Question:
What setting prevented additional mailbox rules from processing?

Answer
StopProcessingRules = True

Evidence:
(Insert screenshot)

Why This Matters:
This configuration ensured the malicious rule executed first and prevented legitimate mailbox rules from interfering with the attacker's objectives.

---

🏁 Flag 13: OneDrive Access Identified

MITRE:
T1213 — Data from Information Repositories

Question:
What Microsoft cloud application was used to access files?

Answer
Microsoft OneDrive for Business

Evidence:
(Insert screenshot)

Why This Matters:
The attacker expanded beyond email access and began collecting information from cloud-hosted storage resources.

---

🏁 Flag 14: SharePoint Access Confirmed

MITRE:
T1213 — Data from Information Repositories

Question:
What additional Microsoft cloud service was accessed?

Answer
SharePoint Online

Evidence:
(Insert screenshot)

Why This Matters:
Access to SharePoint indicates the attacker was attempting to locate business documents, invoices, contracts, and other organizational data.

---

🏁 Flag 15: Cloud File Access Activity

MITRE:
T1213 — Data from Information Repositories

Question:
What activity confirmed the attacker was accessing cloud-hosted data?

Answer
FileAccessed

Evidence:
(Insert screenshot)

Why This Matters:
This event confirms the attacker moved beyond reconnaissance and actively interacted with organizational files stored within Microsoft 365.

---

🏁 Flag 16: Business Email Compromise Target

MITRE:
T1586 — Compromise Accounts

Question:
Which recipient was targeted in the fraudulent invoice campaign?

Answer
j.reynolds@lognpacific.org

Evidence:
(Insert screenshot)

Why This Matters:
Identifying the target recipient helps determine the attacker's intended victim and confirms the objective was financial fraud rather than simple account compromise.

---

🏁 Flag 17: Fraudulent Invoice Subject Line

MITRE:
T1566.003 — Phishing: Spearphishing via Service

Question:
What subject line was used in the fraudulent email?

Answer
RE: Invoice #INV-2026-0892 - Updated Banking Details

Evidence:
(Insert screenshot)

Why This Matters:
The attacker hijacked an existing business conversation to increase credibility and improve the likelihood that the recipient would trust modified payment instructions.

---

🏁 Flag 18: Email Direction Classification

MITRE:
T1078.004 — Valid Accounts: Cloud Accounts

Question:
How was the fraudulent email classified?

Answer
Intra-org

Evidence:
(Insert screenshot)

Why This Matters:
Because the email originated from a legitimate internal account, traditional inbound email security controls were unlikely to detect the message as malicious.

---

🏁 Flag 19: Sender IP Address Verification

MITRE:
T1078.004 — Valid Accounts: Cloud Accounts

Question:
What IP address sent the fraudulent email?

Answer
205.147.16.190

Evidence:
(Insert screenshot)

Why This Matters:
This directly links the email activity to the same attacker infrastructure observed during the initial compromise and cloud access stages.

---

🏁 Flag 20: Azure AD Session Correlation

MITRE:
TA0001 — Initial Access

Question:
What Azure AD session was associated with the attack?

Answer
00225cfa-a0ff-fb46-a079-5d152fcdf72a

Evidence:
(Insert screenshot)

Why This Matters:
This session identifier became the investigative "golden thread," linking authentication events, mailbox rule creation, SharePoint access, and Business Email Compromise activity.

---

🏁 Flag 21: Conditional Access Status

MITRE:
TA0005 — Defense Evasion

Question:
What was the Conditional Access status during the attack?

Answer
notApplied

Evidence:
(Insert screenshot)

Why This Matters:
Conditional Access controls were not enforced against the attacker session, allowing the compromise to proceed without additional authentication restrictions.

---

🏁 Flag 22: MFA Fatigue Technique

MITRE:
T1621 — Multi-Factor Authentication Request Generation

Question:
Which MITRE ATT&CK technique describes the observed MFA abuse?

Answer
T1621

Evidence:
(Insert screenshot)

Why This Matters:
This technique, commonly referred to as MFA fatigue or push bombing, is frequently used by threat actors to bypass multi-factor authentication protections.

---

🏁 Flag 23: Email Hiding Rules Technique

MITRE:
T1564.008 — Hide Artifacts: Email Hiding Rules

Question:
Which MITRE ATT&CK technique describes the malicious inbox rule activity?

Answer
T1564.008

Evidence:
(Insert screenshot)

Why This Matters:
The attacker used inbox rules to suppress security notifications and conceal evidence of compromise, allowing the intrusion to remain active for a longer period.

---

🏁 Flag 24: Initial Credential Source

MITRE:
T1078.004 — Valid Accounts: Cloud Accounts

Question:
What malware category likely provided the initial credentials?

Answer
Infostealer

Evidence:
(Insert screenshot)

Why This Matters:
Infostealers commonly harvest saved passwords, browser data, and authentication tokens which are later sold or shared among threat actors for account compromise operations.

---

🏁 Flag 25: Immediate Containment Action

MITRE:
TA0108 — Containment (Incident Response)

Question:
What should be the first containment action taken by defenders?

Answer
Revoke Sessions

Evidence:
(Insert screenshot)

Why This Matters:
Revoking active sessions immediately invalidates authentication tokens and removes attacker access, preventing further activity while remediation efforts are performed.

---

🏁 Flag 26: Threat Actor Attribution

MITRE:
TA0043 — Reconnaissance / Threat Intelligence Attribution

Question:
Which threat actor group's tradecraft most closely aligns with the observed attack?

Answer
Scattered Spider

Evidence:
(Insert screenshot)

Why This Matters:
The attack exhibited multiple behaviors commonly associated with Scattered Spider, including the use of infostealer-sourced credentials, MFA fatigue attacks, cloud identity compromise, mailbox persistence, and Business Email Compromise (BEC) activity.

---

🏁 Flag 27: Attack Pattern Correlation

MITRE:
T1078.004 — Valid Accounts: Cloud Accounts

Question:
What attack methodology best describes the intrusion?

Answer
Business Email Compromise (BEC)

Evidence:
(Insert screenshot)

Why This Matters:
The attacker leveraged a legitimate Microsoft 365 account to access business communications, monitor financial conversations, and conduct invoice fraud using trusted internal communications.

---

🏁 Flag 28: Cloud Identity Compromise Confirmed

MITRE:
T1078.004 — Valid Accounts: Cloud Accounts

Question:
What type of compromise occurred during this incident?

Answer
Cloud Account Compromise

Evidence:
(Insert screenshot)

Why This Matters:
Rather than exploiting a vulnerability or deploying malware, the attacker abused valid credentials and trusted authentication workflows to gain access to Microsoft 365 services.

---

🏁 Flag 29: Investigation Conclusion

MITRE:
Multiple Techniques Observed

Question:
What was the final assessment of the intrusion?

Answer
Scattered Spider Business Email Compromise

Evidence:
(Insert screenshot)

Why This Matters:
The investigation confirmed a complete attack chain consisting of infostealer-derived credentials, MFA fatigue, malicious inbox rule creation, cloud data access, and attempted financial fraud. The combination of observed TTPs aligns closely with publicly reported Scattered Spider operations targeting Microsoft 365 environments.

---

## 🎯 MITRE ATT&CK Technique Mapping

| Flag(s)        | MITRE Technique                                | ID                      | Description                                                                                                                                                           |
| -------------- | ---------------------------------------------- | ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 2, 3           | Valid Accounts: Cloud Accounts                 | T1078.004               | The attacker successfully authenticated to Microsoft 365 using valid credentials associated with the compromised account `m.smith@lognpacific.org`.                   |
| 4, 5           | Multi-Factor Authentication Request Generation | T1621                   | Multiple MFA prompts were generated in an apparent MFA fatigue attack, ultimately resulting in successful authentication.                                             |
| 6, 13, 14, 15  | Data from Information Repositories             | T1213                   | The attacker accessed Microsoft 365 cloud resources including Outlook Web, OneDrive for Business, and SharePoint Online to locate business and financial information. |
| 10, 11         | Email Collection                               | T1114                   | Malicious inbox rules were created to identify and monitor financial communications containing keywords such as invoice, payment, wire, and transfer.                 |
| 10             | Email Forwarding Rule                          | T1114.003               | An inbox forwarding rule was established to automatically collect and redirect financial communications of interest to the attacker.                                  |
| 12, 23         | Hide Artifacts: Email Hiding Rules             | T1564.008               | Inbox rules were configured to suppress security notifications and hide indicators of compromise from the victim.                                                     |
| 16, 17, 18, 19 | Spearphishing via Service                      | T1566.003               | The attacker abused a legitimate Microsoft 365 account to conduct Business Email Compromise (BEC) activity and distribute fraudulent payment instructions.            |
| 20             | Valid Accounts: Cloud Accounts                 | T1078.004               | A single Azure AD session was used across authentication, mailbox access, SharePoint activity, and BEC operations.                                                    |
| 21             | Impair Defenses                                | T1562                   | Conditional Access protections were not applied to the attacker session, allowing unrestricted access to Microsoft 365 services.                                      |
| 24             | Credentials from Password Stores               | T1555                   | The investigation determined that the initial credentials were likely harvested by infostealer malware prior to the intrusion.                                        |
| 25             | Account Access Removal (Containment)           | IR Activity             | Active sessions were revoked to immediately terminate attacker access and invalidate existing authentication tokens.                                                  |
| 26             | Threat Actor Attribution                       | Intelligence Assessment | Observed tactics, techniques, and procedures aligned closely with publicly reported Scattered Spider operations.                                                      |

### Key ATT&CK Tactics Observed

| Tactic            | Techniques Observed                                               |
| ----------------- | ----------------------------------------------------------------- |
| Initial Access    | T1078.004 – Valid Accounts: Cloud Accounts                        |
| Credential Access | T1621 – Multi-Factor Authentication Request Generation            |
| Persistence       | T1114.003 – Email Forwarding Rule                                 |
| Defense Evasion   | T1564.008 – Email Hiding Rules                                    |
| Collection        | T1114 – Email Collection                                          |
| Collection        | T1213 – Data from Information Repositories                        |
| Impact            | T1566.003 – Spearphishing via Service (Business Email Compromise) |

### ATT&CK Summary

The intrusion was primarily an identity-focused cloud attack rather than a malware-driven compromise. The attacker leveraged valid credentials, abused MFA workflows, established mailbox persistence through malicious inbox rules, collected data from Microsoft 365 services, and ultimately conducted Business Email Compromise activity. The attack chain closely aligns with known Scattered Spider tradecraft and demonstrates how modern adversaries increasingly target cloud identities and business processes instead of traditional endpoints.

---

## 💠 Diamond Model of Intrusion Analysis

```text
+-----------------------------+       +-----------------------------+
|                             |<----->|                             |
|          Adversary          |       |       Infrastructure        |
|       Scattered Spider      |       |    Attacker IP: 205.147...  |
|                             |       |                             |
+-----------------------------+       +-----------------------------+
                ^                                  |
                |                                  v
+-----------------------------+       +-----------------------------+
|           Victim            |<----->|         Capability          |
| Microsoft 365 Tenant        |       | MFA Fatigue (T1621)         |
| m.smith@lognpacific.org     |       | Inbox Rule Persistence      |
|                             |       | OneDrive & SharePoint       |
+-----------------------------+       +-----------------------------+
```

---

# 🔍 Breakdown of Each Node

## 🕵️ Adversary

### **Name/Attribution:**

* Scattered Spider
* Financially motivated threat actor
* Known for cloud identity compromise, MFA fatigue attacks, social engineering, and Business Email Compromise (BEC)

### **Evidence:**

* Successful authentication using valid Microsoft 365 credentials
* MFA fatigue activity consistent with MITRE ATT&CK T1621
* Malicious inbox rule creation for persistence and financial email monitoring
* Access to Outlook Web, OneDrive, and SharePoint Online
* Business Email Compromise activity involving fraudulent invoice communications
* Tradecraft closely aligned with publicly documented Scattered Spider campaigns

---

## 🌐 Infrastructure

### **Microsoft 365 Infrastructure:**

* Microsoft Entra ID (Azure AD)
* Microsoft Outlook Web Access
* Microsoft OneDrive for Business
* Microsoft SharePoint Online

### **Attacker Infrastructure:**

* Attacker IP Address: 205.147.16.190
* Azure AD Session ID:

  * 00225cfa-a0ff-fb46-a079-5d152fcdf72a

### **Cloud Resources Accessed:**

* Outlook Web
* SharePoint Online
* Microsoft OneDrive for Business

### **Persistence Infrastructure:**

* Malicious Inbox Rules
* Email Forwarding Rules
* Email Hiding Rules
* StopProcessingRules = True

---

## 🛠️ Capability

### **Tactics and Techniques:**

* Valid Account Abuse
* MFA Fatigue (Push Bombing)
* Cloud Identity Compromise
* Business Email Compromise (BEC)
* Email Collection
* Cloud Storage Access
* Email Forwarding Rules
* Email Hiding Rules
* Session Abuse
* Financial Fraud

### **MITRE ATT&CK Techniques Observed:**

* T1078.004 — Valid Accounts: Cloud Accounts
* T1621 — Multi-Factor Authentication Request Generation
* T1114 — Email Collection
* T1114.003 — Email Forwarding Rule
* T1213 — Data from Information Repositories
* T1564.008 — Hide Artifacts: Email Hiding Rules

### **Representative Indicators:**

* Compromised Account:

  * [m.smith@lognpacific.org](mailto:m.smith@lognpacific.org)

* Attacker IP:

  * 205.147.16.190

* Financial Keywords:

  * invoice
  * payment
  * wire
  * transfer

* Fraudulent Subject:

  * RE: Invoice #INV-2026-0892 - Updated Banking Details

---

## 🎯 Victim

### **Organization Affected:**

* law-cyber-range Microsoft 365 Tenant

### **Primary Compromised User:**

* [m.smith@lognpacific.org](mailto:m.smith@lognpacific.org)

### **Business Email Compromise Target:**

* [j.reynolds@lognpacific.org](mailto:j.reynolds@lognpacific.org)

### **Targeted Assets:**

* Microsoft Outlook Mailbox
* Business Email Conversations
* Financial Communications
* OneDrive Files
* SharePoint Documents
* Organizational Data Repositories

### **Security Control Gaps Identified:**

* Conditional Access Status:

  * notApplied

* Successful MFA Fatigue Approval

* Active Azure AD Session Maintained Throughout Intrusion

### **Business Impact:**

* Unauthorized access to Microsoft 365 resources
* Financial communication monitoring
* Business Email Compromise (BEC)
* Fraudulent invoice distribution
* Exposure of cloud-hosted business data
* Increased risk of financial loss and reputational damage

---

# 🧾 Conclusion

The Scattered Invoice investigation exposed a sophisticated cloud-based Business Email Compromise (BEC) attack that relied on identity compromise rather than malware deployment. The adversary successfully leveraged credentials likely harvested by an infostealer and bypassed multi-factor authentication through MFA fatigue techniques, ultimately gaining access to a Microsoft 365 environment using legitimate user credentials.

Once authenticated, the attacker established persistence through malicious inbox rules designed to monitor financial communications and suppress security-related notifications. By abusing trusted Microsoft 365 services including Outlook Web, OneDrive for Business, and SharePoint Online, the attacker was able to operate within the environment while blending into legitimate user activity. Analysis of authentication logs, cloud application events, and mailbox activity revealed a coordinated attack chain that progressed from account compromise to Business Email Compromise (BEC) and attempted financial fraud.

The investigation further identified a significant defensive gap, as Conditional Access protections were not applied to the attacker's session. This allowed the adversary to maintain access and interact with multiple Microsoft 365 services without additional authentication restrictions. Session correlation using Azure AD telemetry ultimately linked authentication events, mailbox rule creation, cloud storage access, and fraudulent email activity to a single attacker-controlled session.

Threat intelligence analysis determined that the observed tactics, techniques, and procedures aligned closely with publicly reported Scattered Spider operations. The use of infostealer-derived credentials, MFA fatigue, cloud-native persistence mechanisms, and financial targeting reflects a growing trend among modern threat actors who increasingly focus on identity systems rather than endpoint exploitation.

This threat hunt reinforces several critical defensive lessons:

* Identity systems should be treated as critical assets and monitored with the same priority as endpoints and servers.

* Multi-factor authentication alone is not sufficient protection against social engineering techniques such as MFA fatigue.

* Conditional Access policies should be enforced to restrict access from unfamiliar devices, locations, and risky sign-in activity.

* Inbox rule creation and mailbox forwarding activity should be continuously monitored for indicators of Business Email Compromise.

* Rapid containment actions such as **Revoke Sessions** can significantly reduce attacker dwell time and limit further access to cloud resources.

Ultimately, Scattered Invoice demonstrates that successful cloud attacks often require no malware, no exploits, and no endpoint compromise. A single stolen identity can provide access to email, files, business communications, and financial processes. Organizations that prioritize identity security, conditional access enforcement, and cloud telemetry monitoring are significantly better positioned to detect and disrupt these attacks before financial loss occurs.

---

# 🎓 Lessons Learned

### ***Identity Compromise Can Be More Dangerous Than Malware***

This intrusion demonstrates that attackers do not always need malware, exploits, or ransomware to achieve their objectives. By obtaining valid credentials and successfully bypassing multi-factor authentication, the adversary gained access to email, cloud storage, and business communications using trusted Microsoft 365 services.

### ***MFA Is Not Immune to Social Engineering***

While multi-factor authentication remains a critical security control, the observed MFA fatigue attack highlights that authentication security ultimately depends on user decision-making. Repeated authentication prompts can create opportunities for attackers to exploit trust, confusion, or user frustration to gain access.

### ***Cloud Storage Platforms Contain High-Value Business Data***

The attack extended beyond email into OneDrive for Business and SharePoint Online, demonstrating that cloud storage platforms frequently contain sensitive operational, financial, and organizational information. Monitoring file access activity is just as important as monitoring mailbox activity during cloud investigations.

---

## 🛠️ Recommendations for Remediation

### **1. Strengthen Identity Security Controls**

Treat Microsoft 365 identities as critical assets and enforce strong authentication protections across all user accounts.

* Require phishing-resistant MFA where possible (FIDO2 security keys, Windows Hello for Business).
* Disable legacy authentication protocols.
* Implement risk-based authentication policies.
* Review and remove unused or stale accounts regularly.

---

### **2. Enforce Conditional Access Policies**

The investigation revealed that Conditional Access protections were not applied to the attacker's session.

* Require MFA for all cloud applications.
* Block sign-ins from high-risk locations and anonymous infrastructure.
* Restrict access from unmanaged or unknown devices.
* Implement sign-in risk and user risk policies through Microsoft Entra ID.

---

### **3. Monitor for MFA Fatigue Activity**

Repeated authentication prompts can indicate active compromise attempts.

* Alert on excessive MFA denials or repeated push notifications.
* Educate users to report unexpected MFA requests immediately.
* Consider number matching and additional MFA verification controls.
* Investigate sign-in attempts that generate multiple MFA failures before success.

---

### **4. Monitor Inbox Rule Creation and Modification**

Malicious inbox rules remain one of the most common persistence mechanisms used during Business Email Compromise investigations.

* Alert on creation of new inbox forwarding rules.
* Monitor mailbox rule modifications involving financial keywords.
* Investigate rules containing DeleteMessage or StopProcessingRules actions.
* Review executive and finance mailbox rules regularly.

---

### **5. Detect Business Email Compromise Indicators**

Financial fraud activity often begins with monitoring business communications.

* Monitor emails containing payment, wire transfer, banking, or invoice-related terminology.
* Alert on mailbox forwarding to external recipients.
* Implement verification procedures for banking detail changes.
* Require secondary approval for financial transactions involving updated payment instructions.

---

### **6. Improve Cloud Activity Monitoring**

Visibility across Microsoft 365 services is critical during cloud investigations.

* Continuously monitor Outlook, OneDrive, and SharePoint activity.
* Alert on unusual file access patterns.
* Investigate access from unfamiliar locations or devices.
* Correlate authentication, mailbox, and cloud storage activity during investigations.

---

### **7. Monitor Azure AD Session Activity**

Session correlation played a critical role in reconstructing the attack.

* Track Azure AD Session IDs across authentication and cloud activity.
* Monitor long-lived sessions.
* Alert on session activity originating from unexpected geolocations.
* Investigate simultaneous access from multiple regions.

---

### **8. Improve Threat Detection for Infostealer Exposure**

The investigation suggests the initial credentials were likely harvested through an infostealer infection.

* Monitor for credentials exposed in threat intelligence feeds.
* Require password resets when credential exposure is suspected.
* Implement endpoint protection capable of detecting infostealer malware.
* Encourage password manager usage and unique passwords across services.

---

### **9. Strengthen Incident Response Procedures**

Rapid containment significantly reduces attacker dwell time.

* Document procedures for revoking active sessions.
* Establish workflows for emergency password resets and MFA re-registration.
* Create playbooks for Business Email Compromise investigations.
* Conduct tabletop exercises focused on cloud identity compromise scenarios.

---

### **10. Continuously Validate Defenses Through Threat Hunting**

Use the findings from this investigation to improve proactive detection capabilities.

**Validate detection coverage for:**

* MFA fatigue attacks (T1621)
* Suspicious sign-in activity
* Inbox rule creation and modification
* Email forwarding rules
* OneDrive and SharePoint access anomalies
* Conditional Access policy failures
* Business Email Compromise indicators
* Cloud account abuse (T1078.004)

---

### **Key Takeaway**

This intrusion demonstrates that modern attackers do not always require malware, exploits, or endpoint compromise to achieve their objectives. A single stolen identity combined with MFA fatigue, malicious inbox rules, and access to trusted cloud services can provide everything needed to conduct Business Email Compromise and financial fraud.

Defensive success depends on strong identity security, Conditional Access enforcement, cloud telemetry visibility, and the ability to rapidly detect and contain suspicious authentication activity before attackers gain persistence within Microsoft 365 environments.








