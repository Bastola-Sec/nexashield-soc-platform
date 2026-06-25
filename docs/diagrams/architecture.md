# NexaShield Architecture Diagrams

Three diagrams covering the network layout, SOAR pipeline,
and identity chain. Paste any block into https://mermaid.live
to render and export as PNG or SVG.

## Network Architecture

```mermaid
flowchart TB
    INTERNET[("Internet")]
    subgraph PFS["pfSense-NexaShield"]
        WAN["WAN 10.0.1.3"]
    end
    subgraph V10["vlan10-security 10.0.2.0/24"]
        WAZUH["Wazuh SIEM 10.0.2.4"]
        DOCKER["Keycloak/TheHive/Shuffle 10.0.2.6"]
    end
    subgraph V20["vlan20-redteam 10.0.3.0/29"]
        KALI["Kali 10.0.3.2"]
    end
    subgraph V30["vlan30-endpoints 10.0.6.0/24"]
        SOC["SOC-Workstation 10.0.6.2"]
    end
    subgraph V40["vlan40-servers 10.0.5.0/27"]
        DC["NEXASHIELD-DC 10.0.5.2"]
    end
    subgraph AWS["AWS us-east-2 172.16.0.0/16"]
        EC2["EC2 172.16.2.24"]
    end
    INTERNET <--> WAN
    WAN --- V10
    WAN --- V20
    WAN --- V30
    WAN --- V40
    WAN -. IPsec VPN .-> AWS
```

## SOAR Pipeline

```mermaid
flowchart LR
    A["Attack"] --> W["Wazuh Rule fires"]
    W --> S["Shuffle Webhook"]
    S --> T["TheHive Case created"]
    S --> SL["Slack Notification"]
    S --> AR["iam_lockdown.py Auto containment"]
```

## Identity Chain

```mermaid
flowchart LR
    AD["Active Directory nexashield.local"] -->|LDAP 389| KC["Keycloak 26.6"]
    KC -->|OIDC| SH["Shuffle"]
    KC -->|OIDC| TH["TheHive"]
    KC -->|SAML 2.0| AWS["AWS IAM Identity Center"]
```
