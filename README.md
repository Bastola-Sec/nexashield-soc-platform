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

## Numbers That Matter

- 5 Wazuh agents active (2 Windows, 2 Linux, 1 EC2 via VPN)
- 29 CloudTrail events confirmed flowing into Wazuh
- MTTD under 8 seconds for Sysmon endpoint events
- Full Wazuh to TheHive pipeline under 30 seconds
- 22 security findings documented and mapped to NIST CSF, ISO 27001, CIS v8
- 5 SOAR integration blockers hit and resolved

---

## Automation

Wrote four Python scripts using boto3:

- **aws_audit.py** - checks 5 security controls on every run
- **iam_lockdown.py** - plugs into Wazuh active response, disables a compromised AWS account in under 30 seconds
- **cloudtrail_query.py** - pulls 19 high-value API event types for investigation
- **sync_users.py** - provisions users from AD through Keycloak into AWS IAM Identity Center

---

## Evidence

**Network and Firewall**
- [pfSense all 5 network adapters](docs/screenshots/01-network/pfSense-VM_network%20Adampter%201.png)
- [pfSense dashboard](docs/screenshots/03-firewall/Pfsense_Dashboard.png)
- [Suricata detecting Kali nmap scan](docs/screenshots/03-firewall/suricata-nmap-detected.png)
- [Suricata alerts flowing into Wazuh](docs/screenshots/03-firewall/Suricata_alerts_on_Wazuh.png)
- [pfSense LAN firewall rules](docs/screenshots/03-firewall/pfSense-LAN-interface-rules.png)
- [pfSense ENDPOINTS rules](docs/screenshots/03-firewall/pfSense-endpoint-interface-rules.png)

**Wazuh SIEM**
- [All four agents active](docs/screenshots/02-wazuh/All%20four%20agents%20deployed.png)
- [Wazuh dashboard overview](docs/screenshots/02-wazuh/wazuh-dashboard-overview.png)
- [Sysmon alerts from DC](docs/screenshots/02-wazuh/Wazuh-sysmon-alerts-Nexashield-DC.png)
- [CloudTrail 29 events in Wazuh](docs/screenshots/04-aws/wazuh-cloudtrail-events.png)
- [EC2 Wazuh agent active](docs/screenshots/02-wazuh/Wazuh_agent_on_Ec2.png)

**AWS Cloud**
- [VPC resource map](docs/screenshots/04-aws/vpc-resource-map.png)
- [EC2 client portal running](docs/screenshots/04-aws/ec2-instance-running.png)
- [AWS Config all rules compliant](docs/screenshots/04-aws/config-rules-compliant.png)
- [CloudTrail active](docs/screenshots/04-aws/cloudtrail-logging-active.png)
- [NexaShield portal loaded](docs/screenshots/04-aws/NexaShield%20Portal%20loaded.png)
- [S3 bucket secured](docs/screenshots/04-aws/s3-bucket-properties.png)

**Active Directory and Identity**
- [AD OU structure complete](docs/screenshots/08-ad/ad-complete-structure.png)
- [SOC-Workstation joined to domain](docs/screenshots/08-ad/ad-computers-joined.png)
- [Domain login confirmed](docs/screenshots/08-ad/ad-domain-login-whoami.png)
- [Keycloak federation active](docs/screenshots/08-ad/keycloak-federation-active.png)
- [Keycloak MFA enforced](docs/screenshots/08-ad/Keycloak_MFA_OTP_Enforced.png)
- [AD users synced to AWS](docs/screenshots/08-ad/Successfull-sync_users.py-%20AD_to_AWS.png)
- [EC2 portal login via Keycloak SSO](docs/screenshots/08-ad/Sucessful_authentication_to%20EC2%20portal.png)

**VPN**
- [IPsec tunnel established on pfSense](docs/screenshots/09-vpn/VPN_IPsec_Established%20_on%20pfSense.png)
- [Ping from on-prem to EC2 via VPN](docs/screenshots/09-vpn/Succesfull_ping_from_10.0.2.4_to_VPC_172.16.2.24.png)
- [SOC workstation through VPN to EC2](docs/screenshots/09-vpn/SOC%20workstation%20%E2%86%92%20VPN%20%E2%86%92%20EC2%20%E2%86%92%20nginx..png)
- [AWS VPN connection status](docs/screenshots/09-vpn/AWS_Nexashield-vpn_Status.png)

**SOAR Pipeline**
- [Wazuh to Shuffle to TheHive confirmed](docs/screenshots/10-soar/Wazuh-Shuffle-TheHive-Success.png)
- [TheHive alerts list](docs/screenshots/10-soar/TheHive-Alerts-List-Success.png)
- [TheHive dashboard](docs/screenshots/10-soar/TheHive-Dashboard.png)
- [Shuffle workflow editor](docs/screenshots/10-soar/Shuffle-Workflow-Editor.png)
- [Shuffle SSO login via Keycloak](docs/screenshots/10-soar/Shuffle-SSO-Login.png)
- [Webhook integration on Wazuh](docs/screenshots/10-soar/webhook_integration_for_shuffle_on_wazuh-manager.png)

**FIM Detection Test**
- [Wazuh FIM rule 550 alert](docs/screenshots/11-fim/wazuh-rule550-alert.png)
- [Shuffle execution success](docs/screenshots/11-fim/shuffle-execution-success.png)
- [TheHive FIM alert created](docs/screenshots/11-fim/thehive-fim-alert.png)
- [Slack notification received](docs/screenshots/11-fim/slack-notification.png)

**Vulnerability Assessment**
- [SCA baseline before hardening](docs/screenshots/06-vuln-scan/sca-baseline-before-hardening_BastolaAdministration.png)
- [Vulnerability scan Windows](docs/screenshots/06-vuln-scan/wazuh-vuln-windows-Admin.png)

---

## Author

Riman Bastola - Bastola & KC LLC

Background in financial crime investigation.
Pattern recognition, evidence handling, and adversarial thinking applied to security engineering.

Different arena. Same hunter.

[LinkedIn](https://www.linkedin.com/in/riman-bastola)
