#!/usr/bin/env python3
# NexaShield CloudTrail Investigator
# Pulls the last 24 hours of high-value API events from CloudTrail
# I use this during investigations to get a quick picture of what happened
# For production I would replace this with Athena queries against the S3 bucket
# because lookup_events only goes back 90 days and has rate limits at scale

import boto3
import json
from datetime import datetime, timezone, timedelta
from collections import Counter

cloudtrail = boto3.client('cloudtrail', region_name='us-east-2')

end_time   = datetime.now(timezone.utc)
start_time = end_time - timedelta(hours=24)

# These are the events I care about most during an investigation
# Grouped loosely by category so they are easier to maintain
SUSPICIOUS_EVENTS = [
    # Identity changes
    'ConsoleLogin',
    'CreateUser',
    'DeleteUser',
    'CreateAccessKey',
    'DeleteAccessKey',
    'AttachUserPolicy',
    'DetachUserPolicy',
    'CreatePolicy',
    'PutUserPolicy',
    # Network changes
    'AuthorizeSecurityGroupIngress',
    'RevokeSecurityGroupIngress',
    'DeleteSecurityGroup',
    'CreateNetworkAcl',
    # Audit evasion
    'StopLogging',
    'DeleteTrail',
    # Storage changes
    'PutBucketPolicy',
    'PutBucketAcl',
    # Compute
    'RunInstances',
    'TerminateInstances'
]

print(f"NexaShield CloudTrail Security Query")
print(f"Time range: {start_time.strftime('%Y-%m-%d %H:%M')} to {end_time.strftime('%Y-%m-%d %H:%M')} UTC")
print(f"Querying {len(SUSPICIOUS_EVENTS)} event types...")
print("="*60)

all_events = []

for event_name in SUSPICIOUS_EVENTS:
    try:
        response = cloudtrail.lookup_events(
            LookupAttributes=[{
                'AttributeKey':   'EventName',
                'AttributeValue': event_name
            }],
            StartTime=start_time,
            EndTime=end_time,
            MaxResults=50
            # Note: MaxResults 50 per event type is enough for this environment
            # In production with high volume you would paginate using NextToken
        )

        events = response.get('Events', [])
        if events:
            print(f"\n[!] Found {len(events)} {event_name} event(s):")
            for event in events:
                event_detail = {
                    "EventName": event['EventName'],
                    "EventTime": event['EventTime'].isoformat(),
                    "Username":  event.get('Username', 'N/A'),
                    "SourceIP":  event.get('SourceIPAddress', 'N/A'),
                    "Resources": [r.get('ResourceName', '') for r in event.get('Resources', [])]
                }
                all_events.append(event_detail)

                print(f"    Time:     {event['EventTime'].strftime('%Y-%m-%d %H:%M:%S')} UTC")
                print(f"    User:     {event.get('Username', 'N/A')}")
                print(f"    Source:   {event.get('SourceIPAddress', 'N/A')}")
                if event.get('Resources'):
                    for r in event['Resources']:
                        print(f"    Resource: {r.get('ResourceName', 'N/A')}")
                print()

    except Exception as e:
        print(f"[ERROR] Failed to query {event_name}: {e}")

# Summary
print("="*60)
print(f"QUERY COMPLETE")
print(f"Total privileged events found: {len(all_events)}")

if not all_events:
    print("No suspicious events found in last 24 hours")
else:
    print("\nBreakdown by event type:")
    counts = Counter(e['EventName'] for e in all_events)
    for event_name, count in counts.most_common():
        print(f"  {event_name}: {count}")

output = {
    "query_timestamp": end_time.isoformat(),
    "time_range_hours": 24,
    "total_events":    len(all_events),
    "events":          all_events
}

print(f"\nFull results:")
print(json.dumps(output, indent=2))
