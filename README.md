# Active Directory Threat Detection & Automated SOAR Containment

[![SIEM](https://img.shields.io/badge/SIEM-Wazuh%204.8-2468F2.svg)](https://wazuh.com/)
[![Target](https://img.shields.io/badge/Target-Windows%20Server%202022%20AD-0078D4.svg)](https://microsoft.com/)
[![SOAR](https://img.shields.io/badge/SOAR-Python%20%7C%20LDAP3-3776AB.svg)](https://python.org/)
[![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-T1558-E03C31.svg)](https://attack.mitre.org/)

Practical implementation of an end-to-end detection engineering and automated incident response workflow targeting Kerberos credential attacks (**AS-REP Roasting** and **Kerberoasting**) within an Active Directory Domain Services environment.

---

## 1. Architecture & Threat Modeling

The lab environment models an enterprise Active Directory forest with dedicated detection and attacker nodes:

| Host | Operating System | Role | IP Address | Telemetry / Function |
| :--- | :--- | :--- | :--- | :--- |
| **DC01** | Windows Server 2022 | Primary Domain Controller (`hoang.vn`) | `192.168.50.10` | Advanced Kerberos Audit Subcategories, Wazuh Agent |
| **SIEM-SRV** | Ubuntu 22.04 LTS | SIEM Manager & SOAR Engine | `192.168.50.30` | Wazuh Manager 4.8, Custom Rules, Python LDAP Responder |
| **KALI** | Kali Linux | Adversary Emulation Node | `192.168.50.40` | Impacket Suite (`GetNPUsers`, `GetUserSPNs`) |

### Targeted Attack Vectors (MITRE ATT&CK)

- **AS-REP Roasting (`T1558.004`):** Targeting accounts configured with `DONT_REQ_PREAUTH` (Kerberos Pre-Authentication disabled). An unauthenticated attacker requests a TGT and extracts the encrypted AS-REP response for offline password cracking.
- **Kerberoasting (`T1558.003`):** Authenticated adversaries request Kerberos Service Tickets (TGS) with weak RC4-HMAC (`0x17`) encryption for accounts mapped to Service Principal Names (SPNs), extracting hashes for offline brute-force.

---

## 2. Telemetry & Detection Engineering

### Active Directory Audit Policy Baseline
To reliably capture credential access telemetry on Domain Controllers, granular subcategory auditing was configured via `auditpol`:
- `Kerberos Authentication Service` -> Success & Failure (Generates **Event ID 4768**)
- `Kerberos Service Ticket Operations` -> Success & Failure (Generates **Event ID 4769**)

### Wazuh SIEM Correlation Rules (`local_rules.xml`)
High-severity correlation rules (Level 12) identify RC4 downgrade requests and pre-auth bypass:

```xml
<group name="windows,active_directory_attacks,">

  <!-- Rule 100100: Kerberoasting Request Detection (T1558.003) -->
  <rule id="100100" level="12">
    <if_group>windows</if_group>
    <field name="win.system.eventID">^4769$</field>
    <field name="win.eventdata.ticketEncryptionType">^0x17$</field>
    <description>SOC ALERT: Active Kerberoasting Request Detected (MITRE T1558.003)</description>
    <mitre><id>T1558.003</id></mitre>
  </rule>

  <!-- Rule 100101: AS-REP Roasting Attack Detection (T1558.004) -->
  <rule id="100101" level="12">
    <if_group>windows</if_group>
    <field name="win.system.eventID">^4768$</field>
    <field name="win.eventdata.preAuthType">^0$</field>
    <field name="win.eventdata.ticketEncryptionType">^0x17$</field>
    <description>SOC ALERT: AS-REP Roasting Attack Detected (MITRE T1558.004)</description>
    <mitre><id>T1558.004</id></mitre>
  </rule>

</group>
```

---

## 3. SOAR Implementation & Architectural Decisions

Incident containment is orchestrated via `/var/ossec/integrations/custom-soar.py`, triggered in real-time when Wazuh rules 100100 or 100101 fire.

### Engineering Decisions & Anti-DoS Policy

A common failure mode in naive SOAR playbooks is **automatically disabling accounts upon any security alert**. This playbook addresses critical enterprise constraints:

1. **Anti-DoS Containment Strategy:**
   - **AS-REP Roasting (User Identities):** Automated identity disablement is safe and necessary. The compromised entity is a standard user account (`backupadmin`), and disabling it severs the attacker's foothold without taking down core services.
   - **Kerberoasting (Service Accounts):** Automated identity disablement is **explicitly suppressed**. If an attacker requests TGS tickets for all SPNs in a domain, disabling service accounts would shut down critical business databases and web services (e.g., MSSQL, IIS). Instead, the SOAR engine pages the SOC and flags the attacker's source IP (`192.168.50.40`) for perimeter isolation.

2. **Bitwise `userAccountControl` Modification:**
   - Active Directory stores account flags as a 32-bit bitmask (e.g., `DONT_EXPIRE_PASSWORD = 65536`, `NORMAL_ACCOUNT = 512`).
   - Overwriting UAC directly with a hardcoded integer (like `514`) destroys legitimate account configurations.
   - The script performs a non-destructive bitwise operation: `new_uac = current_uac | 0x0002` (`ACCOUNTDISABLE`), preserving all existing administrative attributes.

3. **Dynamic Directory Traversal:**
   - Accounts rarely reside in the default `CN=Users` container in production.
   - The integration executes a subtree LDAP search filter `(&(objectCategory=person)(objectClass=user)(sAMAccountName={username}))` to resolve the accurate `distinguishedName` regardless of OU depth.

---

## 4. Verification & Forensic Evidence

### Phase 1: Adversary Emulation (Kali Linux)
Executed targeted Kerberos ticket harvesting using Impacket against Domain Controller `192.168.50.10`:
![Red Team Attack Execution](assets/01_kali_attack_emulation.png)

### Phase 2: Domain Controller Security Telemetry
Validation of Event ID 4768 and 4769 logged on `DC01`:
![DC01 Event Viewer Security Logs](assets/02_dc01_kerberos_events.png)

### Phase 3: SIEM Correlation & Alerting (Wazuh Dashboard)
Wazuh ingestion of Windows Security logs and firing of custom Level 12 rules:

| Kerberoasting Detection (Rule 100100) | AS-REP Roasting Detection (Rule 100101) |
| :---: | :---: |
| ![Wazuh Kerberoasting](assets/03_wazuh_kerberoasting_100100.png) | ![Wazuh AS-REP Roasting](assets/03_wazuh_asrep_roasting_100101.png) |

### Phase 4: SOAR Active Directory Containment & SOC Briefings
Identity-level isolation executed in under 3 seconds:

| Automated AD Account Disablement (`dsa.msc`) | Real-Time SOC Telegram Incident Briefing |
| :---: | :---: |
| ![AD Disabled BackupAdmin](assets/05b_ad_account_disabled_containment.png) | ![Telegram Alert](assets/04a_soar_telegram_incident_alert.png) |

---

## 5. Repository Structure

```text
enterprise-soc-detection-and-soar/
├── assets/                                      # Forensic evidence and dashboard captures
│   ├── 01_kali_attack_emulation.png
│   ├── 02_dc01_kerberos_events.png
│   ├── 03_wazuh_asrep_roasting_100101.png
│   ├── 03_wazuh_kerberoasting_100100.png
│   ├── 04a_soar_telegram_incident_alert.png
│   ├── 04b_soar_telegram_incident_alert.png
│   ├── 05a_ad_account_disabled_containment.png
│   └── 05b_ad_account_disabled_containment.png
├── custom-soar.py                               # Production-grade Python LDAP SOAR integration
├── local_rules.xml                              # Custom Wazuh correlation ruleset (Level 12)
└── README.md                                    # Technical documentation & architectural analysis
```

---

## 6. Operational Challenges & Troubleshooting Notes

- **Kerberos Clock Skew (`KRB_AP_ERR_SKEW`):** During initial emulation from Kali, Kerberos authentication failed due to time synchronization drift between VMware host and Domain Controller. Resolved by disabling local host sync daemons and synchronizing UTC clock with DC01 (`ntpdate / date -u`).
- **Wazuh Windows Rule Hierarchy:** Windows Kerberos audit events generated with Audit Success map to parent group `windows` rather than informational syslog SID `60103`. Custom rules were adjusted to inherit `<if_group>windows</if_group>` to ensure 100% correlation fidelity.
- **LDAP Binding Performance:** Switched from external synchronous HTTP modules to standard `urllib.request` with strict timeouts inside the Wazuh integration pipeline to eliminate worker thread blocking during burst authentication events.
