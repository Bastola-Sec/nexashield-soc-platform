# SOAR Deployment Notes

Running Shuffle and TheHive on Ubuntuagent (10.0.2.6) via Docker.
Wazuh sends alerts via webhook, Shuffle creates TheHive cases automatically.

## The pipeline

Wazuh detects something
Webhook fires to Shuffle
Shuffle creates a TheHive alert
Slack notification goes out
If it is rule 80203 (AWS CloudTrail abuse) iam_lockdown.py runs automatically

End to end this happens in under 30 seconds.

## Issues I ran into

### Workers stuck in Created state

Shuffle workers were starting but not picking up any tasks.
Spent a while on this one. Eventually found that there was a stale
Docker Swarm overlay network ID sitting in the shuffle-opensearch index
from an earlier Swarm config attempt. Shuffle was trying to use that
network which no longer existed.

Fix: set SHUFFLE_SWARM_CONFIG= (empty) in docker-compose.yml
Workers started processing immediately after restart.

### Credentials not decrypting after restart

All the API keys and tokens I had saved in Shuffle stopped working
after a container restart. Turned out SHUFFLE_ENCRYPTION_MODIFIER
was not set consistently across all the containers so previously
encrypted values could not be decrypted.

Fix: set a fixed value for SHUFFLE_ENCRYPTION_MODIFIER in
docker-compose.yml and made sure it was the same everywhere.
Had to re-save all credentials after fixing it.

### TheHive app node silently failing

The built-in TheHive app in Shuffle looked like it was succeeding
(green node) but nothing was appearing in TheHive. No error anywhere.
Eventually figured out it was using old TheHive 3.x API endpoints
which do not work with 5.3.

Fix: replaced it with a generic HTTP app node posting directly to
http://thehive:9000/api/v1/alert

Important: use the container DNS name (thehive) not the IP address.
IPs can change between restarts, container names stay stable.

### TheHive SSO reverting on restart

Configured Keycloak SSO in TheHive admin UI but it kept reverting
to broken after every container restart. Found a leftover temp file
in /tmp inside the container that was overriding the database config.

Fix: custom Docker entrypoint script that cleans /tmp/thehive-* files
before TheHive starts.

### Keycloak rejecting Shuffle login

OAuth2 callback was being rejected. Three separate things were wrong:
1. The callback URL was not in the Valid Redirect URIs list in Keycloak
2. Implicit flow was not enabled on the Shuffle client
3. No LDAP attribute mapper for email - Shuffle needs this for user profiles

Fixed all three and login worked.

## Wazuh integration config

Integration block in ossec.conf:
rule_ids: 5710, 5712, 60204, 80203, 100001, 100002, 100003

Confirmed working - alerts visible in Shuffle debug tab with full
JSON payload including agent name, rule level, MITRE ID, source IP.

## FIM test result

Modified a file on the monitored Windows agent.
Wazuh rule 550 fired in under 5 seconds.
Shuffle picked it up, created TheHive alert, sent Slack notification.
Screenshots in docs/screenshots/11-fim/
