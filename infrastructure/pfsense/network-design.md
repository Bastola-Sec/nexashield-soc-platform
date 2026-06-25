# Network Design Notes

## Why pfSense instead of VirtualBox Host-Only adapters

Originally planned to use Host-Only adapters but switched to pfSense
as the central router. The main reason was visibility - with Host-Only
adapters there is no firewall between VMs and no way to run Suricata
on inter-VM traffic. pfSense gives a single chokepoint where everything
passes through and can be inspected.

## VLAN breakdown

| Interface | VLAN | Subnet | Gateway | Purpose |
|---|---|---|---|---|
| em0 | WAN | 10.0.1.3/24 | ISP | Internet via NAT |
| em1 | vlan10-security | 10.0.2.0/24 | 10.0.2.1 | SIEM and IAM servers |
| em2 | vlan20-redteam | 10.0.3.0/29 | 10.0.3.1 | Kali attack platform |
| em3 | vlan40-servers | 10.0.5.0/27 | 10.0.5.1 | Active Directory |
| em4 | vlan30-endpoints | 10.0.6.0/24 | 10.0.6.1 | SOC workstations |

VirtualBox GUI only shows 4 adapter tabs. Added the 5th via CLI:

VBoxManage modifyvm "pfSense-NexaShield" --nic5 intnet --intnet5 "vlan30-endpoints" --nictype5 82540EM --nicpromisc5 allow-all

## Suricata gotchas on VirtualBox

Hardware offloading has to be disabled or Suricata drops packets silently.
Took a while to figure that one out.

Log facility needs to be DAEMON not LOCAL1 - otherwise the syslog routing
to Wazuh breaks and alerts never arrive.

Syslog format needs to be BSD RFC 3164. pfSense defaults to RFC 5424
which Wazuh could not parse correctly.

## AWS VPC

Used 172.16.0.0/16 for the VPC CIDR. Chose this specifically because
the on-prem network is all 10.0.x.x and I wanted room to add a VPN
later without re-addressing anything.

Region: us-east-2 Ohio

Subnets:
  public-dmz          172.16.1.0/24  (ALB, internet-facing)
  private-app         172.16.2.0/24  (EC2 at 172.16.2.24, no public IP)
  database-isolated   172.16.3.0/24  (reserved for future RDS)

## IPsec VPN to AWS

IKEv1, AES-128-CBC, HMAC-SHA1, MODP-1024, NAT-T on UDP 4500
NAT-T was required because pfSense WAN is behind ISP NAT.

Tunnel status: ESTABLISHED

The EC2 Wazuh agent connects back to the manager at 10.0.2.4
through this tunnel instead of over the internet.

## MTU issue with VPN

After the VPN came up the EC2 agent still could not connect.
Root cause was MTU fragmentation - IPsec adds overhead and
oversized packets were being silently dropped.

Fixed it in three places:
- EC2 eth0 MTU set to 1350
- pfSense MSS clamp set to 1300
- Docker bridge MTU set to 1200 (Wazuh runs in Docker on Ubuntuagent)

Had to fix all three or it still failed.
