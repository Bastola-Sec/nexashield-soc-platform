# NexaShield SOC Platform

Built a full hybrid SOC for NexaShield Consulting from the ground up.
This covers everything from network segmentation to cloud integration
to automated incident response. Solo project, all roles covered.

---

## What I Built

**On-premises stack:**
- pfSense as the central router and firewall with 4 isolated VLANs
- Suricata IDS running on 3 interfaces watching all traffic
- Wazuh SIEM collecting logs from every host including AWS
- Active Directory for identity with Keycloak handling SSO and MFA
- TheHive for case management, Shuffle for automation

**Cloud:**
- AWS VPC in us-east-2 with proper 3-tier subnet design
- CloudTrail piped into Wazuh so cloud and on-prem alerts are in one place
- Site-to-site IPsec VPN so the EC2 Wazuh agent talks to the manager privately
- IAM Identity Center connected to Keycloak via SAML so AD credentials work for AWS

---

## Network Layout

| VLAN | Subnet | What lives here |
|---|---|---|
| vlan10-security | 10.0.2.0/24 | Wazuh, Keycloak, TheHive, Shuffle |
| vlan20-redteam | 10.0.3.0/29 | Kali Linux (isolated) |
| vlan40-servers | 10.0.5.0/27 | Active Directory DC |
| vlan30-endpoints | 10.0.6.0/24 | SOC workstation |
| AWS VPC | 172.16.0.0/16 | EC2 client portal, connected via VPN |

Used 172.16.0.0/16 for AWS specifically to avoid overlap with on-prem
ranges when setting up the VPN tunnel.

---

## Numbers that matter

- 5 Wazuh agents active (2 Windows, 2 Linux, 1 EC2 via VPN)
- 29 CloudTrail events confirmed flowing into Wazuh
- MTTD under 8 seconds for Sysmon endpoint events
- Full Wazuh to TheHive pipeline under 30 seconds
- 22 security findings documented and mapped to NIST CSF, ISO 27001, CIS v8
- 5 SOAR integration blockers hit and resolved

---

## Automation

Wrote four Python scripts using boto3:

- **aws_audit.py** — checks 5 security controls on every run
- **iam_lockdown.py** — plugs into Wazuh active response, disables a compromised AWS account in under 30 seconds
- **cloudtrail_query.py** — pulls 19 high-value API event types for investigation
- **sync_users.py** — provisions users from AD through Keycloak into AWS IAM Identity Center

---

## Evidence

Screenshots in docs/screenshots/ organised by component.
Key ones worth looking at:

- `09-vpn/VPN_IPsec_Established_on pfSense.png` — tunnel confirmed
- `04-aws/wazuh-cloudtrail-events.png` — 29 CloudTrail events in Wazuh
- `10-soar/Wazuh-Shuffle-TheHive-Success.png` — end-to-end pipeline
- `11-fim/slack-notification.png` — FIM triggered Slack alert
- `08-ad/Successfull-sync_users.py- AD_to_AWS.png` — AD to AWS sync

---

## Author

Riman Bastola — Bastola & KC LLC
Background in financial crime investigation.
Different arena. Same hunter.

https://linkedin.com/in/YOUR_LINKEDIN_URL
