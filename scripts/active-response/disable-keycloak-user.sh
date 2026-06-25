#!/bin/bash
# Wazuh active response script - disable Keycloak user
# Triggered by Wazuh rule 100003 (Keycloak brute force detected)
# Runs on Ubuntuagent (10.0.2.6) where Keycloak container is running
#
# Wazuh passes alert JSON via stdin
# Script extracts username and calls Keycloak admin API to disable account

KEYCLOAK_URL="http://localhost:8080"
REALM="Nexashield"
ADMIN_USER="admin"
ADMIN_PASS="YOUR_KEYCLOAK_ADMIN_PASSWORD"
LOG_FILE="/var/ossec/logs/active-response.log"

log() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') [disable-keycloak-user] $1" >> "$LOG_FILE"
}

# Read alert from stdin (Wazuh pipes JSON here)
read -r ALERT_JSON

# Extract username from alert
USERNAME=$(echo "$ALERT_JSON" | python3 -c "
import json, sys
data = json.load(sys.stdin)
try:
    username = data['parameters']['alert']['data']['userId']
    print(username)
except (KeyError, TypeError):
    print('')
")

if [ -z "$USERNAME" ]; then
  log "ERROR: Could not extract username from alert"
  exit 1
fi

log "Brute force detected - disabling Keycloak user: $USERNAME"

# Get admin token
TOKEN=$(curl -s -X POST \
  "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$ADMIN_USER" \
  -d "password=$ADMIN_PASS" \
  -d "grant_type=password" \
  -d "client_id=admin-cli" | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")

if [ -z "$TOKEN" ]; then
  log "ERROR: Failed to get Keycloak admin token"
  exit 1
fi

# Get user ID
USER_ID=$(curl -s \
  "$KEYCLOAK_URL/admin/realms/$REALM/users?username=$USERNAME" \
  -H "Authorization: Bearer $TOKEN" | python3 -c "
import json,sys
users = json.load(sys.stdin)
if users: print(users[0]['id'])
else: print('')
")

if [ -z "$USER_ID" ]; then
  log "ERROR: User $USERNAME not found in Keycloak"
  exit 1
fi

# Disable the user
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -X PUT \
  "$KEYCLOAK_URL/admin/realms/$REALM/users/$USER_ID" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"enabled": false}')

if [ "$HTTP_STATUS" = "204" ]; then
  log "SUCCESS: Disabled Keycloak user $USERNAME (ID: $USER_ID)"
else
  log "ERROR: Failed to disable user $USERNAME - HTTP $HTTP_STATUS"
  exit 1
fi
