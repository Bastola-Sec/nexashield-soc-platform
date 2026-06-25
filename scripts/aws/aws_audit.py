#!/usr/bin/env python3
# NexaShield AWS Security Audit
# Runs 5 security checks against the AWS account and outputs findings
# I run this manually when I need a quick posture check
# For production I would schedule this as a Lambda or EventBridge rule
# and pipe results into a SIEM rather than writing to a local log file

import boto3
import json
from datetime import datetime, timezone

# Clients for the services we are checking
# I used us-east-2 because that is where the NexaShield infrastructure lives
iam = boto3.client('iam', region_name='us-east-2')
s3  = boto3.client('s3',  region_name='us-east-2')
ec2 = boto3.client('ec2', region_name='us-east-2')

findings  = []
timestamp = datetime.now(timezone.utc).isoformat()

def add_finding(severity, title, resource, detail, recommendation):
    # Append a structured finding to the list
    # Using a dict so we can dump to JSON at the end for Wazuh ingestion
    findings.append({
        "timestamp":      timestamp,
        "source":         "nexashield-aws-audit",
        "severity":       severity,
        "title":          title,
        "resource":       resource,
        "detail":         detail,
        "recommendation": recommendation
    })


# Check 1: Root access keys
# Root keys are the highest risk credential in any AWS account
# They cannot be scoped or restricted so they should never exist
print("[*] Checking root account access keys...")
try:
    summary   = iam.get_account_summary()
    root_keys = summary['SummaryMap'].get('AccountAccessKeysPresent', 0)
    if root_keys > 0:
        add_finding(
            severity="CRITICAL",
            title="Root Account Access Keys Exist",
            resource="AWS Root Account",
            detail=f"Root account has {root_keys} active access key(s). These provide unrestricted access to everything.",
            recommendation="Delete root access keys immediately. Use IAM users or roles with least privilege instead."
        )
    else:
        print("[OK] No root access keys found")
except Exception as e:
    print(f"[ERROR] Root key check failed: {e}")


# Check 2: MFA on IAM users
# Every human IAM user should have MFA enabled
# I enforce this via password policy but this check catches anything that slipped through
print("[*] Checking MFA on IAM users...")
try:
    users = iam.list_users()['Users']
    for user in users:
        mfa_devices = iam.list_mfa_devices(UserName=user['UserName'])['MFADevices']
        if not mfa_devices:
            add_finding(
                severity="HIGH",
                title="IAM User Without MFA",
                resource=f"IAM User: {user['UserName']}",
                detail=f"User {user['UserName']} has no MFA device registered.",
                recommendation="Enable MFA on all human IAM users. Consider using IAM Identity Center instead of local IAM users."
            )
        else:
            print(f"[OK] MFA enabled: {user['UserName']}")
except Exception as e:
    print(f"[ERROR] MFA check failed: {e}")


# Check 3: S3 public access
# Any public S3 bucket in this environment is a misconfiguration
# I have block public access enabled at account level but this double checks ACLs
print("[*] Checking S3 bucket public access...")
try:
    buckets = s3.list_buckets()['Buckets']
    for bucket in buckets:
        try:
            acl = s3.get_bucket_acl(Bucket=bucket['Name'])
            for grant in acl['Grants']:
                grantee = grant.get('Grantee', {})
                if grantee.get('URI') in [
                    'http://acs.amazonaws.com/groups/global/AllUsers',
                    'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
                ]:
                    add_finding(
                        severity="CRITICAL",
                        title="S3 Bucket Publicly Accessible via ACL",
                        resource=f"S3 Bucket: {bucket['Name']}",
                        detail=f"Bucket {bucket['Name']} has a public ACL grant.",
                        recommendation="Remove public ACL grants and verify block public access settings are enabled."
                    )
        except Exception:
            pass
    print(f"[OK] Checked {len(buckets)} S3 buckets")
except Exception as e:
    print(f"[ERROR] S3 check failed: {e}")


# Check 4: Security groups with dangerous ports open to the internet
# These ports should never be 0.0.0.0/0 in a production environment
# In the lab I allow SSH from specific IPs only but this catches any drift
print("[*] Checking security groups for unrestricted access...")
try:
    sgs = ec2.describe_security_groups()['SecurityGroups']
    # Ports that should never be open to 0.0.0.0/0
    dangerous_ports = [22, 3389, 3306, 5432, 1433, 27017]
    for sg in sgs:
        for rule in sg.get('IpPermissions', []):
            port = rule.get('FromPort', 0)
            for ip_range in rule.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0' and port in dangerous_ports:
                    add_finding(
                        severity="HIGH",
                        title="Security Group Open to Internet on Sensitive Port",
                        resource=f"Security Group: {sg['GroupId']} ({sg['GroupName']})",
                        detail=f"Port {port} is open to 0.0.0.0/0.",
                        recommendation=f"Restrict port {port} to specific trusted IP ranges only."
                    )
    print(f"[OK] Checked {len(sgs)} security groups")
except Exception as e:
    print(f"[ERROR] Security group check failed: {e}")


# Check 5: IAM password policy
# I set this to 14 char minimum with complexity and 90 day expiry
# This verifies it has not been changed
print("[*] Checking IAM password policy...")
try:
    policy = iam.get_account_password_policy()['PasswordPolicy']
    if policy.get('MinimumPasswordLength', 0) < 14:
        add_finding(
            severity="MEDIUM",
            title="Weak IAM Password Policy",
            resource="IAM Password Policy",
            detail=f"Minimum password length is {policy.get('MinimumPasswordLength')} characters, should be 14 or more.",
            recommendation="Update password policy to require at least 14 characters."
        )
    else:
        print("[OK] Password policy meets requirements")
except Exception as e:
    print(f"[ERROR] Password policy check failed: {e}")


# Output results
print(f"\n{'='*50}")
print(f"NexaShield AWS Security Audit Results")
print(f"Timestamp: {timestamp}")
print(f"Total Findings: {len(findings)}")
print(f"{'='*50}")

if findings:
    for i, finding in enumerate(findings, 1):
        print(f"\n[{i}] {finding['severity']}: {finding['title']}")
        print(f"    Resource:       {finding['resource']}")
        print(f"    Detail:         {finding['detail']}")
        print(f"    Recommendation: {finding['recommendation']}")
else:
    print("\n[OK] No security findings detected")

# Save to JSON for Wazuh ingestion
# In production this would write to an S3 bucket and trigger a Lambda
# For now local file is fine since Wazuh picks it up from /var/log/
output_file = f"/var/log/nexashield-audit-{datetime.now().strftime('%Y%m%d')}.json"
try:
    with open(output_file, 'w') as f:
        json.dump({
            "audit_timestamp": timestamp,
            "total_findings":  len(findings),
            "findings":        findings
        }, f, indent=2)
    print(f"\n[*] Results saved to: {output_file}")
except Exception as e:
    print(f"[*] Could not write to file (probably not running as root): {e}")
    print(json.dumps(findings, indent=2))
