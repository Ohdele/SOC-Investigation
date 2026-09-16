# SOC Investigations

## Overview
This project is a set of SOC case studies in a controlled AD + Linux lab, using Wazuh, Windows Security Logs, Sysmon, and Linux telemetry to investigate suspicious activity, correlate events, and conclude on compromise evidence. Each case includes detection logic, queries, supporting evidence, correlation, and final conclusion.

# Case Study 01 — Credential Attack Investigation

## Threat Name
Brute-force / weak-password authentication

### Objective
Assess failed and successful logons for signs of brute-force compromise.

### Hunt Hypothesis
Repeated failures followed by success may indicate account compromise.

### Detection Strategy
- **Sources:** Wazuh, Windows Security Logs, Sysmon
- **Indicators:** Event IDs 4625 (failures), 4624 (success), 1 (process)
- **Queries:**

```text
Event ID 4625 — Failed logons
data.win.system.eventID: 4625

Event ID 4624 — Successful logons for john.smith
data.win.system.eventID: 4624 AND data.win.eventdata.targetUserName: john.smith

Sysmon Event ID 1 — Process creation
data.win.system.eventID: 1
```

### Investigation
- 21 failed logons (DC1: 5, WS01: 16).
- john.smith: **Aug 27, 2026 @ 15:59:16.772 → Sep 1, 2026 @ 15:04:04.049**, primarily Logon Type 2 from `127.0.0.1` on WS01.
- Administrator: **Aug 27, 2026 @ 08:02:45.380 → Sep 4, 2026 @ 08:04:40.171**, with Logon Types 2, 7, and 11.
- 219 john.smith successful logons; histogram analysis narrowed the investigation to **Aug 27, 2026 @ 06:56:31.619 → 11:57:00.254**.
- 53 Type 3 logons from WS01 (`192.168.56.102`) to DC1; no failed → successful correlation.
- 75 process events within the same window. The relevant activity at **Aug 27, 2026 @ 09:10:48.968 → 09:13:15.161** was tied to `NT AUTHORITY\SYSTEM` with the Wazuh agent as parent, not john.smith.

### Findings & Summary
No evidence of brute-force success, account compromise, or follow-on activity attributable to john.smith was established from the available evidence.

### Who, What, When, Where, Why, How
- **Who:** john.smith; Administrator
- **What:** Failed and successful authentication activity
- **When:** **Aug 27, 2026 @ 08:02:45.380 → Sep 4, 2026 @ 08:04:40.171**
- **Where:** DC1, WS01
- **Why:** Not established from available evidence
- **How:** Windows authentication events collected by Wazuh

### Recommendations
Monitor repeated failures and correlate future successful logons with endpoint activity.

### Evidence
- Wazuh authentication logs — Event ID 4625 failed logons.
- Sysmon Event ID 1 — process activity correlated within the successful-logon investigation window.

![Case 01 — Event ID 4625 Failed Logons](Screenshot%201/case1-credential-attack-4625-evidence.png)

## Operational Impact
Shows evidence-based authentication investigation without misattributing system activity.

---


# Case Study 02 — AD Reconnaissance

## Threat Name
NTLM-based network authentication

### Objective
Investigate NTLM-based network authentication linked to the activity and determine if it progressed into additional activity on DC1.

### MITRE ATT&CK
- **Technique:** T1078 — Valid Accounts
- **Tactic:** Credential Access

### Hunt Hypothesis
Remote NTLM authentication with Administrator may indicate unauthorized network access and could lead to further activity.

### Detection Strategy
- **Evidence Sources:** Wazuh, Windows Security Logs
- **Suspicious Indicators:** NTLM Type 3 logons, source IP `192.168.56.115`, destination DC1, Administrator account, Logon ID `0x7b8e69`, Events 4624, 4634, 4672
- **Queries:**

```text
Event ID 4624 — NTLM authentication from 192.168.56.115
data.win.system.eventID: "4624" AND @timestamp >= "2026-09-01T15:25:21.363Z" AND @timestamp <= "2026-09-02T18:01:53.646Z" AND data.win.eventdata.ipAddress: "192.168.56.115"

Session lifecycle — Logon ID 0x7b8e69
data.win.eventdata.targetLogonId: "0x7b8e69" AND @timestamp >= "2026-09-01T15:25:21.363Z" AND @timestamp <= "2026-09-02T18:01:53.646Z"

Event ID 4624 — Successful logons during session
@timestamp >= "2026-09-02T18:01:53.646Z" AND @timestamp <= "2026-09-02T18:03:33.788Z" AND data.win.system.eventID: 4624

Event ID 4672 — Special privileges during session
@timestamp >= "2026-09-02T18:01:53.646Z" AND @timestamp <= "2026-09-02T18:03:33.788Z" AND data.win.system.eventID: 4672

Event ID 4672 — Direct Logon ID correlation
data.win.system.eventID: "4672" AND data.win.eventdata.subjectLogonId: "0x7b8e69"
```

### Investigation
- Repeated NTLM Type 3 authentications from `192.168.56.115` to DC1, primarily using Administrator.
- Session `0x7b8e69`: logon at **Sep 2, 2026 @ 18:01:53.646**, logoff at **18:03:33.788** (duration 1m 40.142s).
- Event ID 4672 confirmed special privileges including SeDebug, SeBackup, SeRestore, and SeImpersonate.
- No process creation (Event ID 1) or service creation (Event ID 7045) was observed during the session.

### Findings & Summary
Confirmed NTLM-based Administrator authentication from `192.168.56.115` to DC1, followed by a privileged session. Evidence shows authentication and privilege assignment, but no progression into process or service activity. Potential lateral-movement activity is indicated, but lateral movement is not confirmed.

### Who, What, When, Where, Why, How
- **Who:** `DELEDFIR\Administrator` from `192.168.56.115`
- **What:** NTLM Type 3 network authentication and privileged session
- **When:** **Sep 1, 2026 @ 15:25:21.363 → Sep 2, 2026 @ 18:03:33.788**; confirmed session **Sep 2, 2026 @ 18:01:53.646 → 18:03:33.788**
- **Where:** Source `192.168.56.115` → DC1
- **Why:** Not established from available evidence
- **How:** NTLM authentication (4624), privilege assignment (4672), and logoff (4634)

### Recommendations
- Monitor NTLM authentication involving privileged accounts.
- Correlate authenticated sessions with process and service telemetry.
- Investigate privileged sessions from unexpected sources.
- Improve endpoint visibility during NTLM sessions.

### Evidence

![Case 02 — NTLM Session Lifecycle](Screenshot%202/ntlm-session-lifecycle.png)

![Case 02 — NTLM Privileged Session](Screenshot%202/ntlm-privileged-session-4672.png)

## Operational Impact
Provides evidence-based analysis of NTLM privileged sessions while distinguishing confirmed authentication activity from unconfirmed lateral movement.

---


# Case Study 03 — JML Account Changes

## Threat Name
Joiner/Mover/Leaver (JML) account changes — enable/disable and group-membership activity

## Objective

Investigate account enable/disable and group-membership changes, distinguishing legitimate IAM activity from potential unauthorized manipulation.

## MITRE ATT&CK
Technique: T1098 — Account Manipulation  
Tactic: Persistence

## Hunt Hypothesis
Unexpected account changes or privileged group modifications may indicate unauthorized manipulation.

## Detection Strategy
Evidence Sources: Wazuh, Windows Security Logs
Suspicious Indicators: Account enable/disable (4722, 4725), group-membership changes (4728)

Queries:
    data.win.system.eventID: (4722 OR 4725)
    data.win.system.eventID: "4728"

## Investigation
- 16 enable/disable events across DC1 and WS01 involving Guest, student1, and WazuhTest.
- All changes were associated with the Administrators account.
- 2 group-membership events (4728) on WS01; affected member not captured (`targetUserName=None`).

## Findings & Summary
Confirmed account enable/disable and group-membership changes. Activity documented as IAM events, not automatically malicious. Attribution is limited by missing member detail in the 4728 events.

## Who, What, When, Where, Why, How
Who: Guest, student1, WazuhTest, Administrators  
What: Account enable/disable and group changes  
When: Aug 27, 2026 @ 15:41:13.950 → Aug 29, 2026 @ 18:49:30.291  
Where: DC1 and WS01  
Why: Not established  
How: Security Events 4722, 4725, and 4728 via Wazuh

## Recommendations
- Monitor sensitive account changes.
- Correlate group modifications with admin activity and change records.
- Improve telemetry to capture affected members in 4728 events.
- Review unexpected privileged group changes.

## Evidence

![Case 03 — JML Account Enable/Disable Activity](Screenshot%203/jml-account-enable-disable.png)

![Case 03 — JML Group Membership Changes](Screenshot%203/jml-group-membership.png)

## Operational Impact
Demonstrates detection of account lifecycle and group-membership changes while identifying a telemetry gap that limits attribution of affected members in Event 4728.
