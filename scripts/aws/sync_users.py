#!/usr/bin/env python3
# NexaShield User Sync - AD to AWS IAM Identity Center
#
# The problem: Keycloak does not have built-in SCIM provisioning
# so creating users in Keycloak does not automatically create them in AWS.
# This script bridges that gap by reading from AD directly and pushing to AWS.
#
# I used ldap3 to query AD directly instead of going through the Keycloak REST API
# because the Keycloak API runs in READ_ONLY mode for LDAP-synced users and
# returns empty group membership lists. Going straight to AD solved that.
#
# For production I would use a proper SCIM provisioning plugin for Keycloak
# or build a Lambda-based bridge so this runs automatically on any AD change.
# Vetting any third party SCIM plugin carefully before using it in production
# is important since it gets read access to your entire directory.

import requests
import boto3
import json
import sys
from datetime import datetime

# Suppress SSL warnings - using self-signed cert in the lab
# In production you would use a proper cert and remove this
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Keycloak settings
KEYCLOAK_URL   = "https://10.0.2.6:8443"
REALM          = "Nexashield"
CLIENT_ID      = "nexashield-wazuh-response"
CLIENT_SECRET  = "YOUR_CLIENT_SECRET"  # replaced for security

# AWS settings
AWS_REGION        = "us-east-2"
IDENTITY_STORE_ID = "YOUR_IDENTITY_STORE_ID"  # replaced for security
INSTANCE_ARN      = "YOUR_INSTANCE_ARN"        # replaced for security

# AD settings - using direct LDAP because Keycloak REST API returns empty
# group membership for READ_ONLY LDAP-synced users
LDAP_HOST          = "10.0.5.2"
LDAP_PORT          = 389
# Note: in production switch to LDAPS on port 636 with a proper cert
# Port 389 is fine in this isolated lab environment but not for production
LDAP_BIND_DN       = "CN=Keycloak Service,OU=Security,OU=NexaShield,DC=nexashield,DC=local"
LDAP_BIND_PASSWORD = "YOUR_SERVICE_ACCOUNT_PASSWORD"  # replaced for security
LDAP_BASE_DN       = "OU=NexaShield,DC=nexashield,DC=local"

VERIFY_SSL = False  # self-signed cert in lab, set True in production
DRY_RUN    = False  # set True to test without making changes
LOG_PREFIX = "[NexaShield-Sync]"


def should_skip_user(username):
    # Skip computer accounts, service accounts, and built-in AD accounts
    # These should not be provisioned in AWS
    if username.endswith('$'):
        return True
    if username.startswith('svc.'):
        return True
    if username.lower() in ['administrator', 'guest', 'krbtgt', 'defaultaccount']:
        return True
    return False


def get_keycloak_token():
    # Client credentials grant - Keycloak issues a token for the script
    # not for a specific user
    url     = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token"
    payload = {
        "grant_type":    "client_credentials",
        "client_id":     CLIENT_ID,
        "client_secret": CLIENT_SECRET
    }
    print(f"{LOG_PREFIX} Requesting Keycloak token...")
    response = requests.post(url, data=payload, verify=VERIFY_SSL)
    if response.status_code == 200:
        print(f"{LOG_PREFIX} Token obtained")
        return response.json()["access_token"]
    else:
        print(f"{LOG_PREFIX} ERROR: Could not get token - {response.status_code}")
        print(f"{LOG_PREFIX} {response.text}")
        sys.exit(1)


def get_keycloak_groups(token):
    url     = f"{KEYCLOAK_URL}/admin/realms/{REALM}/groups"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    print(f"{LOG_PREFIX} Fetching groups from Keycloak...")
    response = requests.get(url, headers=headers, verify=VERIFY_SSL)
    if response.status_code == 200:
        groups = response.json()
        print(f"{LOG_PREFIX} Found {len(groups)} groups")
        for g in groups:
            print(f"{LOG_PREFIX}   - {g['name']}")
        return groups
    else:
        print(f"{LOG_PREFIX} ERROR: {response.status_code} - {response.text}")
        sys.exit(1)


def get_keycloak_users(token):
    url     = f"{KEYCLOAK_URL}/admin/realms/{REALM}/users"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    params  = {"max": 1000}
    # max=1000 covers this environment easily
    # for larger directories you would paginate using first and max params
    print(f"{LOG_PREFIX} Fetching users from Keycloak...")
    response = requests.get(url, headers=headers, params=params, verify=VERIFY_SSL)
    if response.status_code == 200:
        all_users = response.json()
        users     = [u for u in all_users if not should_skip_user(u['username'])]
        print(f"{LOG_PREFIX} Total in Keycloak: {len(all_users)}")
        print(f"{LOG_PREFIX} Skipped:           {len(all_users) - len(users)} service/computer accounts")
        print(f"{LOG_PREFIX} Syncing:           {len(users)} users")
        for u in users:
            print(f"{LOG_PREFIX}   - {u['username']} ({u.get('email', 'no email')})")
        return users
    else:
        print(f"{LOG_PREFIX} ERROR: {response.status_code}")
        sys.exit(1)


def get_group_memberships_from_ad():
    # I tried using the Keycloak REST API to get group members first
    # but it returned 0 members for every group because the users are
    # LDAP-synced in READ_ONLY mode and Keycloak does not resolve
    # group membership for those users via the API.
    # Querying AD directly with ldap3 was the reliable fix.
    from ldap3 import Server, Connection, ALL

    print(f"{LOG_PREFIX} Querying AD directly for group memberships...")
    try:
        server = Server(LDAP_HOST, port=LDAP_PORT, get_info=ALL)
        conn   = Connection(server, user=LDAP_BIND_DN, password=LDAP_BIND_PASSWORD, auto_bind=True)
        print(f"{LOG_PREFIX} Connected to AD at {LDAP_HOST}")

        # First get all users so we can map CN to sAMAccountName
        # AD stores group members as full DNs so we need this lookup
        conn.search(LDAP_BASE_DN, '(objectClass=user)', attributes=['cn', 'sAMAccountName'])
        cn_to_username = {str(e.cn): str(e.sAMAccountName) for e in conn.entries}
        print(f"{LOG_PREFIX} Found {len(cn_to_username)} users in AD")

        # Now get groups and resolve member CNs to usernames
        conn.search(LDAP_BASE_DN, '(objectClass=group)', attributes=['cn', 'member'])
        group_memberships = {}

        for entry in conn.entries:
            group_name = str(entry.cn)
            members    = []
            if entry.member:
                for member_dn in entry.member:
                    cn       = str(member_dn).split(',')[0].replace('CN=', '')
                    username = cn_to_username.get(cn, cn)
                    members.append(username)
            group_memberships[group_name] = members
            print(f"{LOG_PREFIX}   {group_name}: {len(members)} members")

        conn.unbind()
        return group_memberships

    except Exception as e:
        print(f"{LOG_PREFIX} WARNING: Could not reach AD - {e}")
        print(f"{LOG_PREFIX} Skipping membership sync this run")
        return {}


def get_aws_users():
    print(f"{LOG_PREFIX} Fetching existing AWS IAM Identity Center users...")
    try:
        client    = boto3.client('identitystore', region_name=AWS_REGION)
        aws_users = {}
        paginator = client.get_paginator('list_users')
        for page in paginator.paginate(IdentityStoreId=IDENTITY_STORE_ID):
            for user in page['Users']:
                aws_users[user['UserName']] = user['UserId']
                print(f"{LOG_PREFIX}   - {user['UserName']}")
        print(f"{LOG_PREFIX} Found {len(aws_users)} existing users in AWS")
        return aws_users
    except Exception as e:
        print(f"{LOG_PREFIX} ERROR: {e}")
        sys.exit(1)


def get_aws_groups():
    print(f"{LOG_PREFIX} Fetching existing AWS IAM Identity Center groups...")
    try:
        client     = boto3.client('identitystore', region_name=AWS_REGION)
        aws_groups = {}
        paginator  = client.get_paginator('list_groups')
        for page in paginator.paginate(IdentityStoreId=IDENTITY_STORE_ID):
            for group in page['Groups']:
                aws_groups[group['DisplayName']] = group['GroupId']
                print(f"{LOG_PREFIX}   - {group['DisplayName']}")
        print(f"{LOG_PREFIX} Found {len(aws_groups)} existing groups in AWS")
        return aws_groups
    except Exception as e:
        print(f"{LOG_PREFIX} ERROR: {e}")
        sys.exit(1)


def create_aws_group(group_name, aws_groups):
    if group_name in aws_groups:
        print(f"{LOG_PREFIX} SKIP: Group already exists - {group_name}")
        return aws_groups[group_name]
    if DRY_RUN:
        print(f"{LOG_PREFIX} [DRY RUN] Would create group: {group_name}")
        return None
    try:
        client   = boto3.client('identitystore', region_name=AWS_REGION)
        response = client.create_group(
            IdentityStoreId=IDENTITY_STORE_ID,
            DisplayName=group_name,
            Description=f"Synced from AD group: {group_name}"
        )
        group_id = response['GroupId']
        print(f"{LOG_PREFIX} CREATED group: {group_name} ({group_id})")
        return group_id
    except Exception as e:
        print(f"{LOG_PREFIX} ERROR creating group {group_name}: {e}")
        return None


def create_aws_user(user, aws_users):
    username = user['username']
    if username in aws_users:
        print(f"{LOG_PREFIX} SKIP: User already exists - {username}")
        return aws_users[username]
    if DRY_RUN:
        print(f"{LOG_PREFIX} [DRY RUN] Would create user: {username}")
        return None
    # AWS requires an email address for every user
    # If the AD account has no email we generate a placeholder
    # In production all AD accounts should have the mail attribute populated
    email = user.get('email') or f"{username}@nexashield.local"
    try:
        client   = boto3.client('identitystore', region_name=AWS_REGION)
        response = client.create_user(
            IdentityStoreId=IDENTITY_STORE_ID,
            UserName=username,
            DisplayName=f"{user.get('firstName', '')} {user.get('lastName', '')}".strip() or username,
            Name={
                "GivenName":  user.get('firstName', username),
                "FamilyName": user.get('lastName', username)
            },
            Emails=[{"Value": email, "Type": "work", "Primary": True}]
        )
        user_id = response['UserId']
        print(f"{LOG_PREFIX} CREATED user: {username} ({user_id})")
        return user_id
    except Exception as e:
        print(f"{LOG_PREFIX} ERROR creating user {username}: {e}")
        return None


def assign_user_to_group(username, user_id, group_name, group_id):
    if not user_id or not group_id:
        print(f"{LOG_PREFIX} SKIP: Missing ID for {username} to {group_name}")
        return
    if DRY_RUN:
        print(f"{LOG_PREFIX} [DRY RUN] Would assign {username} to {group_name}")
        return
    try:
        client = boto3.client('identitystore', region_name=AWS_REGION)
        client.create_group_membership(
            IdentityStoreId=IDENTITY_STORE_ID,
            GroupId=group_id,
            MemberId={"UserId": user_id}
        )
        print(f"{LOG_PREFIX} ASSIGNED: {username} to {group_name}")
    except client.exceptions.ConflictException:
        print(f"{LOG_PREFIX} SKIP: {username} is already in {group_name}")
    except Exception as e:
        print(f"{LOG_PREFIX} ERROR assigning {username} to {group_name}: {e}")


if __name__ == "__main__":
    print(f"{LOG_PREFIX} {'='*50}")
    print(f"{LOG_PREFIX} NexaShield User Sync - {datetime.now()}")
    if DRY_RUN:
        print(f"{LOG_PREFIX} MODE: DRY RUN - no changes will be made")
    else:
        print(f"{LOG_PREFIX} MODE: LIVE - changes will be applied to AWS")
    print(f"{LOG_PREFIX} {'='*50}")

    token             = get_keycloak_token()
    keycloak_groups   = get_keycloak_groups(token)
    keycloak_users    = get_keycloak_users(token)
    group_memberships = get_group_memberships_from_ad()
    aws_users         = get_aws_users()
    aws_groups        = get_aws_groups()

    print(f"\n{LOG_PREFIX} Syncing groups...")
    updated_aws_groups = dict(aws_groups)
    for group in keycloak_groups:
        group_id = create_aws_group(group['name'], aws_groups)
        if group_id:
            updated_aws_groups[group['name']] = group_id

    print(f"\n{LOG_PREFIX} Syncing users...")
    updated_aws_users = dict(aws_users)
    for user in keycloak_users:
        user_id = create_aws_user(user, aws_users)
        if user_id:
            updated_aws_users[user['username']] = user_id

    print(f"\n{LOG_PREFIX} Syncing group memberships...")
    for group_name, members in group_memberships.items():
        group_id = updated_aws_groups.get(group_name)
        for username in members:
            user_id = updated_aws_users.get(username)
            assign_user_to_group(username, user_id, group_name, group_id)

    print(f"\n{LOG_PREFIX} {'='*50}")
    print(f"{LOG_PREFIX} SYNC COMPLETE")
    print(f"{LOG_PREFIX} Keycloak users:  {len(keycloak_users)}")
    print(f"{LOG_PREFIX} Keycloak groups: {len(keycloak_groups)}")
    print(f"{LOG_PREFIX} AWS users:       {len(updated_aws_users)}")
    print(f"{LOG_PREFIX} AWS groups:      {len(updated_aws_groups)}")
    if DRY_RUN:
        print(f"{LOG_PREFIX} Set DRY_RUN=False to apply changes for real")
