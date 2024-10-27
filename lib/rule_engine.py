# lib/rule_engine.py

from typing import Dict, Any, List
from lib.rules import enrichment_rules, custom_event_rules
from lib.metadata import AwsMetadata

class RuleEngine:
    def __init__(self, metadata: AwsMetadata):
        self.metadata = metadata

    def enrich_event(self, event: Dict[str, Any]):
        """Apply enrichment rules to the event."""
        for rule_func in enrichment_rules:
            rule_func(event, self.metadata)

    def generate_custom_events(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate custom events based on the event."""
        custom_events = []
        for rule_func in custom_event_rules:
            custom_event = rule_func(event, self.metadata)
            if custom_event:
                custom_events.append(custom_event)
        return custom_events