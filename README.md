# NexaShield: Federated Hybrid SOC & Identity Infrastructure

Architected, deployed, and validated an enterprise-grade hybrid Security Operations Center (SOC) and defensive security architecture from the ground up. This engineering project bridges micro-segmented on-premises network boundaries with an AWS cloud ecosystem via an encrypted IPsec VPN tunnel, culminating in real-time telemetry correlation and automated active threat containment.

---

## Core Architectural Pillars

### Infrastructure Engineering & Network Security

- **Micro-Segmented Topology:** Engineered 5 isolated VLAN zones utilizing a virtualized pfSense Next-Generation Firewall to enforce strict zone-based access control policies and eliminate lateral movement.
- **Inline Threat Detection:** Deployed Suricata IDS across 3 critical interfaces, performing deep packet inspection against an active ruleset of over 20,000 intrusion signatures.
- **Enterprise Identity Fabric:** Configured an Active Directory Domain Controller (`nexashield.local`) federated directly into a Keycloak Identity Tier, enforcing TOTP Multi-Factor Authentication across both internal endpoints and cloud instances.

### Security Operations & SOAR Automation

- **Centralized Log Aggregation:** Implemented a distributed Wazuh SIEM cluster correlating system events via Windows Sysmon and Linux auditd logs with native AWS cloud telemetry.
- **Orchestration Pipeline:** Designed containerized Shuffle SOAR playbooks to parse streaming SIEM notifications, dynamically trigger incident response notifications, and programmatically open cases inside TheHive.
- **Active Incident Response:** Wrote multi-platform automation utilities utilizing the Python `boto3` SDK and Bash to systematically quarantine compromised entities and block adversarial infrastructure.

---

## Network Segmentation & Subnet Blueprint

| Network Zone | Subnet Boundary | Core Infrastructure Component | Functional Security Posture |
| :--- | :--- | :--- | :--- |
| **VLAN 10: Security** | `10.0.2.0/24` | Wazuh Manager, Keycloak Core, TheHive, Shuffle | Isolated management and orchestration boundary |
| **VLAN 20: Red Team** | `10.0.3.0/29` | Kali Linux Threat Emulation Nodes | Completely isolated, non-routable attack sandbox |
| **VLAN 30: Endpoints** | `10.0.6.0/24` | Dedicated SOC Analyst Workstations | Restricted ingress/egress mapped to analyst roles |
| **VLAN 40: Servers** | `10.0.5.0/27` | Active Directory Domain Controller (NEXASHIELD-DC) | High-value asset enclave, heavily audited domain tier |
| **AWS Production VPC** | `172.16.0.0/16` | 3-Tier Subnet Topology (ALB, App, DB Layer) | External production cluster connected via AWS VGW |

> **Engineering Note:** The AWS VPC address space was intentionally provisioned within the `172.16.0.0/16` CIDR boundary to explicitly eliminate routing collisions or subnet overlap across the Site-to-Site IPsec VPN tunnel interface.

---

## Operational Performance Metrics

- **Comprehensive Telemetry Coverage:** 5 active enterprise Wazuh agents deployed across heterogeneous nodes (2 Windows Server/Client endpoints, 2 Linux application clusters, 1 external cloud EC2 instance).
- **Cloud Observability:** Verified integration of streaming AWS CloudTrail logs tracking 29 specific high-value API events natively in the SIEM dashboard.
- **Detection Efficiency:** Mean Time to Detect (MTTD) endpoint Sysmon modifications clocked at **under 8 seconds**.
- **Automated Mitigation:** End-to-end event-to-containment pipeline (Wazuh to Shuffle SOAR to TheHive to Active Response Block) fully executed in **under 30 seconds**.
- **Governance Rigor:** Conducted an exhaustive posture assessment producing 22 documented security findings mapped directly to **NIST CSF 2.0**, **ISO/IEC 27001:2022**, and **CIS Critical Security Controls v8**.

---

## Security Automation Suite

The platform utilizes custom Python and Bash automation frameworks housed within the `/scripts/` directory to facilitate rapid auditing and containment:

- [`/scripts/aws/aws_audit.py`](scripts/aws/aws_audit.py): A compliance utility that scans the AWS tenant programmatically to audit 5 fundamental security baselines (MFA enforcement, security group drift, S3 public block verification).
- [`/scripts/active-response/iam_lockdown.py`](scripts/active-response/iam_lockdown.py): An active response webhook utility tied directly to Wazuh alerts that interacts with AWS IAM to instantly strip keys and attach an explicit Deny policy to compromised accounts in **under 30 seconds**.
- [`/scripts/aws/cloudtrail_query.py`](scripts/aws/cloudtrail_query.py): A forensic utility built to mine 19 high-value, reconnaissance-indicative API events from raw CloudTrail buckets during an investigation.
- [`/scripts/aws/sync_users.py`](scripts/aws/sync_users.py): An identity sync orchestration script that reads Active Directory attributes and provisions access groups through Keycloak into the AWS IAM Identity Center via automated SAML flows.

---

## Structural Engineering Evidence

### Network Architecture & Gateway Security

| Verification Objective | Evidence |
| :--- | :--- |
| Virtualized pfSense Network Interface Allocations | [View Adapter Config](docs/screenshots/01-network/pfsense-vm_network_adampter_1.png) |
| Core pfSense Next-Gen Firewall Control Panel | [View Firewall Dashboard](docs/screenshots/03-firewall/pfsense_dashboard.png) |
| Inline Suricata IDS Nmap Reconnaissance Capture | [View Network Intrusion Alert](docs/screenshots/03-firewall/suricata-nmap-detected.png) |
| Suricata Network Alerts Streaming into Wazuh SIEM | [View Consolidated IDS Stream](docs/screenshots/03-firewall/suricata_alerts_on_wazuh.png) |
| pfSense Corporate LAN Ingress/Egress Rule Matrix | [View Local Security Policy](docs/screenshots/03-firewall/pfsense-lan-interface-rules.png) |
| pfSense Endpoint Zone VLAN Rule Segregation | [View Endpoint Policy Rules](docs/screenshots/03-firewall/pfsense-endpoint-interface-rules.png) |

### SIEM Monitoring & Cloud Telemetry

| Verification Objective | Evidence |
| :--- | :--- |
| Enterprise Wazuh EDR Fleet Status Summary | [View Agent Standings](docs/screenshots/02-wazuh/all_four_agents_deployed.png) |
| Unified SIEM Security Operations Dashboard | [View Threat Dashboard](docs/screenshots/02-wazuh/wazuh-dashboard-overview.png) |
| Domain Controller Windows Sysmon Alert Logs | [View Active Directory Auditing](docs/screenshots/02-wazuh/wazuh-sysmon-alerts-nexashield-dc.png) |
| AWS CloudTrail Control Plane API Stream Parsing | [View Cloud Telemetry Logs](docs/screenshots/04-aws/wazuh-cloudtrail-events.png) |
| Remote EC2 Instance Monitoring Status via VPN Tunnel | [View Cloud EDR Agent](docs/screenshots/02-wazuh/wazuh_agent_on_ec2.png) |

### AWS Infrastructure Security & Controls

| Verification Objective | Evidence |
| :--- | :--- |
| 3-Tier Production Cloud VPC Network Mapping Layout | [View Cloud Topology](docs/screenshots/04-aws/vpc-resource-map.png) |
| Active EC2 Client Application Cluster Status | [View Compute Dashboard](docs/screenshots/04-aws/ec2-instance-running.png) |
| AWS Config Continuous Compliance Evaluation Engine | [View Security Baseline State](docs/screenshots/04-aws/config-rules-compliant.png) |
| Global CloudTrail Audit Logging Verification Status | [View Audit Status](docs/screenshots/04-aws/cloudtrail-logging-active.png) |
| Production Client Portal Frontend Ingress Resolution | [View Live Portal Interface](docs/screenshots/04-aws/nexashield_portal_loaded.png) |
| S3 Object Storage Bucket Public Access Isolation Block | [View Bucket Policy](docs/screenshots/04-aws/s3-bucket-properties.png) |

### Identity Access Management & Single Sign-On

| Verification Objective | Evidence |
| :--- | :--- |
| Active Directory Hierarchical Organisation Unit Layout | [View OU Configuration](docs/screenshots/08-ad/ad-complete-structure.png) |
| Corporate Analyst Workstation Active Domain Bound Status | [View Workstation Trust](docs/screenshots/08-ad/ad-computers-joined.png) |
| Verified Kerberos Domain Login Identity Resolution | [View Identity Execution](docs/screenshots/08-ad/ad-domain-login-whoami.png) |
| Keycloak Active Directory User Federation Pipeline | [View LDAP Core Sync](docs/screenshots/08-ad/keycloak-federation-active.png) |
| Mandatory Time-Based OTP MFA Inbound Challenge Page | [View Enforced Challenge](docs/screenshots/08-ad/keycloak_mfa_otp_enforced.png) |
| Automated Python Synchronized Provisioning Execution Log | [View Sync Execution](docs/screenshots/08-ad/successfull-sync_users.py-_ad_to_aws.png) |
| Federated AWS Management Console SAML Entry Pass | [View Single Sign-On Event](docs/screenshots/08-ad/sucessful_authentication_to_ec2_portal.png) |

### Encrypted Transport & Hybrid VPN Boundaries

| Verification Objective | Evidence |
| :--- | :--- |
| On-Premises Phase 1/Phase 2 IPsec Security Association | [View pfSense Tunnel Status](docs/screenshots/09-vpn/vpn_ipsec_established__on_pfsense.png) |
| Private ICMP Transit Routing across VPN Gateways | [View Tunnel Network Ping](docs/screenshots/09-vpn/succesfull_ping_from_10.0.2.4_to_vpc_172.16.2.24.png) |
| End-to-End Private Path Verification (Workstation to Cloud) | [View Multi-Hop Trace Proof](docs/screenshots/09-vpn/route_table_showing_aws_private_subnet_using_vpn_gateway_for_internal_network_10.0.0.0.png) |
| AWS Virtual Private Gateway Connection Status | [View Cloud VPN Interface](docs/screenshots/09-vpn/aws_nexashield-vpn_status.png) |

### Incident Response Automation & SOAR Workflows

| Verification Objective | Evidence |
| :--- | :--- |
| Cross-Platform API Integration Inter-Connectivity Proof | [View System Handshake](docs/screenshots/10-soar/wazuh-shuffle-thehive-success.png) |
| TheHive Security Case Management Ingress Log Index | [View Opened Incidents](docs/screenshots/10-soar/thehive-alerts-list-success.png) |
| Live Incident Analytics and Resolution Statistics Panel | [View Case Dashboards](docs/screenshots/10-soar/thehive-dashboard.png) |
| Shuffle Visual Orchestration Workflow Architecture | [View Automation Map](docs/screenshots/10-soar/shuffle-workflow-editor.png) |
| Federated Identity Single Sign-On Access to SOAR | [View Identity Entry Page](docs/screenshots/10-soar/shuffle-sso-login.png) |
| Wazuh Internal Webhook JSON Streaming Output | [View Native Webhook Node](docs/screenshots/10-soar/webhook_integration_for_shuffle_on_wazuh-manager.png) |

### File Integrity Monitoring Real-Time Validation

| Verification Objective | Evidence |
| :--- | :--- |
| Wazuh syscheck Directory Modification Generation Capture | [View SIEM Modification Log](docs/screenshots/11-fim/wazuh-rule550-alert.png) |
| Shuffle SOAR Direct Webhook Ingress and Step Parsing Log | [View Automation Run Proof](docs/screenshots/11-fim/shuffle-execution-success.png) |
| TheHive Automatic Forensic Case Opening Payload Injection | [View Automated Incident Case](docs/screenshots/11-fim/thehive-fim-alert.png) |
| Real-Time Slack SOC Channel Emergency Notification Alert | [View App Notification Output](docs/screenshots/11-fim/slack-notification.png) |

### Posture Evaluation & Threat Management

| Verification Objective | Evidence |
| :--- | :--- |
| Wazuh SCA Baseline Audit Report Prior to System Hardening | [View Unhardened Baseline Audit](docs/screenshots/06-vuln-scan/sca-baseline-before-hardening_bastolaadministration.png) |
| Infrastructure Host Kernel/Package Vulnerability Scan Logs | [View OS CVE Report Screen](docs/screenshots/06-vuln-scan/wazuh-vuln-windows-admin.png) |

---

## Author Profile

**Riman Bastola** - Cybersecurity Analyst & Infrastructure Security Engineer

Principal Specialist at **Bastola & KC LLC** (NexaShield Consulting).
Leveraging a professional background within complex financial intelligence, fraud analytics, and corporate anti-money laundering investigations. Engineering practice directly applies enterprise data pattern recognition, forensic evidence custody tracking, and adversarial modeling to building resilient, automated corporate infrastructures.

- **LinkedIn:** [linkedin.com/in/riman-bastola](https://www.linkedin.com/in/riman-bastola)
- **Full Compliance Framework Posture Review:** Read the [Comprehensive Architecture Risk Assessment Report](docs/AUDIT_REPORT.md)
