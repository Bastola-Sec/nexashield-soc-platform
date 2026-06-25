# NexaShield Security Audit Report

**Conducted by:** Riman Bastola, Bastola & KC LLC
**Scope:** NexaShield Consulting hybrid SOC infrastructure
**Frameworks:** NIST CSF 2.0, ISO 27001:2022, CIS Controls v8

---

## Risk Summary

| Severity | Count | Resolved | Open |
|---|---|---|---|
| Critical | 2 | 2 | 0 |
| High | 5 | 3 | 2 |
| Medium | 11 | 3 | 8 |
| Low | 4 | 1 | 3 |
| Total | 22 | 9 | 13 |

---

## Findings Register

| ID | Finding | Severity | MITRE | Status |
|---|---|---|---|---|
| AF-001 | SHUFFLE_ENCRYPTION_MODIFIER empty in docker-compose | Critical | T1078 | Resolved |
| AF-002 | Default Keycloak admin credentials active post-install | Critical | T1078.001 | Resolved |
| AF-003 | Default TheHive admin credentials active post-install | High | T1078.001 | Resolved |
| AF-004 | TLS certificate verification disabled internally | High | T1557 | Accepted - Phase 2 |
| AF-005 | Docker socket mounted in Shuffle containers | High | T1611 | Accepted - Phase 2 |
| AF-006 | Keycloak HTTP on port 8080 accessible internally | High | T1557 | Mitigated - nginx TLS on 8443 |
| AF-007 | LDAP unencrypted port 389 (LDAPS 636 not implemented) | High | T1557 | Accepted - Phase 2 |
| AF-008 | Incomplete AD user attributes - missing email field | Medium | T1078 | Resolved - LDAP mapper added |
| AF-009 | Shuffle implicit OAuth flow enabled | Medium | T1550 | Accepted - required for lab SSO |
| AF-010 | svc.keycloak not using Group Managed Service Account | Medium | T1078.003 | Phase 2 recommendation |
| AF-011 | No log retention policy defined | Medium | T1562.006 | Phase 2 |
| AF-012 | Wazuh indexer heap manually reduced to 1GB | Medium | - | Accepted - lab RAM constraint |
| AF-013 | AWS CLI credentials stored in plain text on disk | Medium | T1552.001 | Accepted - chmod 600 applied |
| AF-014 | EC2 access via SSH keypair instead of SSM Session Manager | Low | T1021.004 | Phase 2 recommendation |
| AF-015 | No site-to-site VPN between on-premises and AWS | Medium | T1040 | Resolved - IPsec VPN established |
| AF-016 | AWS IAM Identity Center account instance limitation | Medium | - | Open - requires AWS Organizations |
| AF-017 | Domain controller on shared security VLAN | Medium | T1018 | Resolved - moved to vlan40-servers |
| AF-018 | pfSense WAN rule allows all inbound traffic | High | T1190 | Open - Phase 2 review |
| AF-019 | Shuffle local admin account active alongside SSO | Low | T1078 | Phase 2 |
| AF-020 | No version control for scripts at build start | Low | - | Resolved - GitHub repo created |
| AF-021 | Docker containers running as root user | Medium | T1611 | Accepted - Phase 2 |
| AF-022 | Self-signed certificates across all internal services | Low | T1557 | Accepted - lab |

---

## Compliance Mapping

| Control Domain | NIST CSF 2.0 | ISO 27001:2022 | CIS Controls v8 |
|---|---|---|---|
| Asset inventory | ID.AM | A.5.9 | Control 1, 2 |
| Access control | PR.AA | A.5.15, A.8.3 | Control 5, 6 |
| Data protection | PR.DS | A.8.24 | Control 3 |
| Network security | PR.IR | A.8.20, A.8.22 | Control 12, 13 |
| Log management | DE.CM | A.8.15, A.8.16 | Control 8 |
| Incident response | RS.MA | A.5.26 | Control 17 |
| Vulnerability management | ID.RA | A.8.8 | Control 7 |

---

## Remediation Roadmap

### Phase 2 - Security Audit and Hardening
- Implement LDAPS on port 636
- Replace SSH with SSM Session Manager for EC2
- Enable AWS Organizations for IAM Identity Center
- Define and implement log retention policy
- Review and tighten pfSense WAN rules
- Replace service account with gMSA for Keycloak bind

### Phase 3 - Red Team Validation
- Run 10 MITRE ATT&CK scenarios from Kali
- Validate all detection rules fire correctly
- Measure MTTD per attack scenario
- Document residual gaps post-remediation
