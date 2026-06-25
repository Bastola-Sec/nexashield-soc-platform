# NexaShield AWS Automation Scripts

## Scripts in this folder

| Script | Purpose |
|---|---|
| aws_audit.py | AWS security posture check - 5 controls |
| iam_lockdown.py | Automated credential containment via Wazuh active response |
| cloudtrail_query.py | Privileged API activity investigation - 19 event types |
| sync_users.py | AD to AWS IAM Identity Center user provisioning |

## Note

Scripts are stored on BastolaUbuntuDEV (10.0.2.4).
Will be added in next commit when VM is running.

## iam_lockdown.py - How It Works

Triggered by Wazuh rule 80203 (CloudTrail abuse event).
Reads alert JSON from stdin, extracts IAM username,
then executes three containment steps:

1. Disable all access keys
2. Delete console login profile
3. Attach DenyAll inline policy

Mean time to contain: under 30 seconds automated.
