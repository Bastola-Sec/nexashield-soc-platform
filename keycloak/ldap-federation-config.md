# Keycloak LDAP Federation

Keycloak 26.6 running on Ubuntuagent (10.0.2.6) federated to
Active Directory on NEXASHIELD-DC (10.0.5.2).

The goal was one set of credentials for everything -
Windows login, Keycloak, TheHive, Shuffle, and AWS console
all authenticate against the same AD account.

## Connection settings

Vendor: Active Directory
Connection URL: ldap://10.0.5.2
Bind DN: CN=Keycloak Service,OU=Security,OU=NexaShield,DC=nexashield,DC=local
Users DN: OU=NexaShield,DC=nexashield,DC=local
Username attribute: sAMAccountName
UUID attribute: objectGUID
Search Scope: Subtree
Edit Mode: READ_ONLY

## Things that went wrong

### Bind DN format

First tried using just "svc.keycloak" as the bind DN.
LDAP simple bind needs the full Distinguished Name.
Changed it to the full CN= format and it connected.

Tested with ldapsearch from Ubuntuagent to confirm
before trying in Keycloak UI.

### Zero users after sync

Sync completed successfully but imported 0 users.
Search Scope was set to One Level which only looks at
immediate children of the Users DN.

The users are not directly under NexaShield OU -
they are inside Security, IT, and Clients sub-OUs.
One Level does not go that deep.

Changed to Subtree and 14 users imported immediately.

### LDAP port blocked

Windows Firewall on the DC was blocking port 389 inbound.
Not obvious because the connection test said "connected"
but the actual bind was timing out.

Added firewall rules for TCP and UDP 389 on the DC.

## Applications connected via OIDC

shuffle - Shuffle SOAR
thehive - TheHive 5.3
nexashield-portal - EC2 client portal

MFA enforced via TOTP as a realm-required action.
Users set it up on first login.

## AWS IAM Identity Center

Set up Keycloak as external SAML 2.0 IdP for AWS.
AD group memberships map to permission sets:

SOCAnalysts  gets SecurityAudit
ITAdmins     gets AdministratorAccess
ClientUsers  gets ReadOnlyAccess

Note: console access was blocked by AWS account instance
limitation (needs AWS Organizations). Everything else in
the chain works - SAML trust confirmed, users synced,
permission sets assigned. Just the final org step missing.
