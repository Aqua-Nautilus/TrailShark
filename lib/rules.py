# lib/rules.py

from typing import Dict, Any
from lib.metadata import AwsMetadata

enrichment_rules = []
custom_event_rules = []

def enrichment(func):
    enrichment_rules.append(func)
    return func

def rule(func):
    custom_event_rules.append(func)
    return func

def custom_event(func):
    custom_event_rules.append(func)
    return func

@enrichment
def enrich_made_by_recorder(event: Dict[str, Any], metadata: AwsMetadata):
    """Enrich event with 'madeByRecorder' flag."""
    if event.get('userIdentity', {}).get('arn') == metadata.username:
        event['madeByRecorder'] = 1
    else:
        event['madeByRecorder'] = 0

@enrichment
def enrich_derivative_event(event: Dict[str, Any], metadata: AwsMetadata):
    """Enrich event with 'derivativeEvent' flag."""
    if (event['madeByRecorder'] and 
        (event.get('userAgent', '').endswith('com') or event.get('userAgent') == 'AWS Internal')) or \
       (event.get('eventSource', '').endswith('com') and 
        event.get('sourceIPAddress', '').endswith('com') and 
        event.get('sourceIPAddress') != event.get('eventSource')):
        event['derivativeEvent'] = 1
    else:
        event['derivativeEvent'] = 0

@rule
def unknown_bucket_rule(event: Dict[str, Any], metadata: AwsMetadata):
    """Generate custom event for unknown buckets."""
    parameters = event.get('requestParameters')
    if parameters and parameters.get("bucketName") and parameters["bucketName"] not in metadata.buckets:
        metadata.buckets.append(parameters["bucketName"])
        unknown_bucket_event = {
            'eventName': "UnknownBucket(Rule)",
            'requestParameters': parameters["bucketName"],
            'madeByRecorder': event['madeByRecorder']
        }
        return unknown_bucket_event
    return None

@enrichment
def shadow_resource_created(event: Dict[str, Any], metadata: AwsMetadata):
    """Modify eventName if a shadow resource is created."""
    event_name = event.get('eventName', '')
    if (('Put' in event_name or 'Create' in event_name) and event.get('derivativeEvent') == 1):
        new_event_name = f"ShadowResourceCreated - {event_name.replace('Create', '').replace('Put', '').strip()}"
        event['eventName'] = new_event_name