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
  - 4625 failures
  - 4624 successes for john.smith
  - Sysmon Event ID 1

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