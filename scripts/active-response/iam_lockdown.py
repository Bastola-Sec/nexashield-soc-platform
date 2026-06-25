#!/usr/bin/env python3
# NexaShield IAM Emergency Lockdown
# Disables a compromised AWS IAM user immediately
#
# Two ways to trigger this:
# 1. Wazuh active response - fires automatically on rule 80203 (CloudTrail abuse)
#    Wazuh pipes the alert JSON to stdin and the script extracts the username
# 2. Manual - python3 iam_lockdown.py <username>
#    Use this when you need to lock someone down right now during an incident
#
# Three things happen in order:
#   1. All access keys disabled
#   2. Console login profile deleted
#   3. DenyAll inline policy attached
#
# For production I would add SNS notification so the team gets alerted
# when a lockdown fires, and write the result to CloudTrail via a custom event.
# Right now it just prints to stdout which Wazuh captures in its logs.

import boto3
import sys
import json
from datetime import datetime, timezone


def lockdown_user(username):
    iam       = boto3.client('iam', region_name='us-east-2')
    timestamp = datetime.now(timezone.utc).isoformat()
    actions   = []

    print(f"[{timestamp}] LOCKDOWN INITIATED: {username}")
    print("="*60)

    # Step 1: Disable all access keys
    # Not deleting them yet - disabling is reversible if this turns out to be a false positive
    # In production you might want to delete immediately depending on your policy
    print("[*] Disabling access keys...")
    try:
        keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
        if not keys:
            print("    No access keys found")
        for key in keys:
            iam.update_access_key(
                UserName=username,
                AccessKeyId=key['AccessKeyId'],
                Status='Inactive'
            )
            print(f"    [OK] Disabled: {key['AccessKeyId']}")
            actions.append(f"Disabled access key: {key['AccessKeyId']}")
    except Exception as e:
        print(f"    [ERROR] {e}")

    # Step 2: Remove console login profile
    # This stops the user logging in via the AWS console
    print("[*] Removing console access...")
    try:
        iam.delete_login_profile(UserName=username)
        print("    [OK] Console access removed")
        actions.append("Removed console login profile")
    except iam.exceptions.NoSuchEntityException:
        print("    No console access to remove")
    except Exception as e:
        print(f"    [ERROR] {e}")

    # Step 3: Attach DenyAll inline policy
    # Even if they have access keys we missed or assume a role, this blocks everything
    # Named EMERGENCY-LOCKDOWN so it is obvious what it is when reviewing the account
    print("[*] Attaching DenyAll policy...")
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect":   "Deny",
            "Action":   "*",
            "Resource": "*"
        }]
    }
    try:
        iam.put_user_policy(
            UserName=username,
            PolicyName='EMERGENCY-LOCKDOWN-DENYALL',
            PolicyDocument=json.dumps(deny_policy)
        )
        print("    [OK] DenyAll policy attached")
        actions.append("Attached DenyAll inline policy")
    except Exception as e:
        print(f"    [ERROR] {e}")

    # Summary
    print("\n" + "="*60)
    print(f"LOCKDOWN COMPLETE: {username}")
    print(f"Timestamp: {timestamp}")
    print(f"Actions taken: {len(actions)}")
    for action in actions:
        print(f"  - {action}")
    print("="*60)
    print("\nNext steps:")
    print("1. Check CloudTrail for everything this user did in the last 24 hours")
    print("2. Look for any resources they created (EC2, IAM roles, S3 buckets)")
    print("3. Rotate any secrets or credentials they had access to")
    print("4. Document the incident in TheHive")

    return {
        "timestamp": timestamp,
        "username":  username,
        "actions":   actions,
        "status":    "LOCKED_DOWN"
    }


if __name__ == "__main__":
    # Check if being called by Wazuh (stdin) or manually (argv)
    if not sys.stdin.isatty():
        # Wazuh active response mode - alert JSON comes in via stdin
        try:
            alert     = json.load(sys.stdin)
            username  = alert['parameters']['alert']['data']['aws']['userIdentity']['userName']
            print(f"[Wazuh active response] Triggered for user: {username}")
        except (KeyError, json.JSONDecodeError) as e:
            print(f"[ERROR] Could not parse Wazuh alert: {e}")
            sys.exit(1)
    elif len(sys.argv) == 2:
        # Manual mode
        username = sys.argv[1]
    else:
        print("Usage: python3 iam_lockdown.py <username>")
        print("Or pipe a Wazuh alert JSON via stdin for active response mode")
        sys.exit(1)

    result = lockdown_user(username)
    print(f"\nResult: {json.dumps(result, indent=2)}")
