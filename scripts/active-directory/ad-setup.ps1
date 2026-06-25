# AD setup script for NEXASHIELD-DC
# Ran this on the Windows Server 2022 VM after promoting to DC
# Domain: nexashield.local

# Install the role first
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Promote to DC - this reboots the server automatically
Install-ADDSForest `
  -DomainName "nexashield.local" `
  -DomainNetbiosName "NEXASHIELD" `
  -ForestMode "WinThreshold" `
  -DomainMode "WinThreshold" `
  -InstallDns:$true `
  -SafeModeAdministratorPassword `
    (ConvertTo-SecureString "YOUR_DSRM_PASSWORD" -AsPlainText -Force) `
  -Force:$true

# After reboot - create the OU structure
New-ADOrganizationalUnit -Name "NexaShield"   -Path "DC=nexashield,DC=local"
New-ADOrganizationalUnit -Name "Security"     -Path "OU=NexaShield,DC=nexashield,DC=local"
New-ADOrganizationalUnit -Name "IT"           -Path "OU=NexaShield,DC=nexashield,DC=local"
New-ADOrganizationalUnit -Name "Clients"      -Path "OU=NexaShield,DC=nexashield,DC=local"
New-ADOrganizationalUnit -Name "Workstations" -Path "OU=NexaShield,DC=nexashield,DC=local"

# Groups
New-ADGroup -Name "SOCAnalysts" -GroupScope Global -GroupCategory Security `
  -Path "OU=Security,OU=NexaShield,DC=nexashield,DC=local"
New-ADGroup -Name "ITAdmins" -GroupScope Global -GroupCategory Security `
  -Path "OU=IT,OU=NexaShield,DC=nexashield,DC=local"
New-ADGroup -Name "ClientUsers" -GroupScope Global -GroupCategory Security `
  -Path "OU=Clients,OU=NexaShield,DC=nexashield,DC=local"

# Users - passwords replaced with placeholder
# 14 users total across Security, IT, Clients OUs
# Service accounts svc.keycloak and svc.wazuh have PasswordNeverExpires set

# Domain join for SOC-Workstation
# Add-Computer failed with error 50 on Windows 11 in VirtualBox
# Used djoin.exe offline domain join instead:
#
# On DC:
# djoin /provision /domain nexashield.local /machine SOC-Workstation /savefile C:\djoin-blob.txt /machineou "OU=Workstations,OU=NexaShield,DC=nexashield,DC=local" /reuse
#
# On workstation:
# djoin /requestodj /loadfile C:\djoin-blob.txt /windowspath C:\Windows /localos
# Restart-Computer -Force

# Verify
Get-ADDomainController | Select Name, IPv4Address, IsGlobalCatalog
Get-ADUser -Filter * | Select Name, SamAccountName, Enabled | Sort Name
Get-ADGroup -Filter * | Select Name | Sort Name
