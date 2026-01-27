#!/usr/bin/env python3
"""
Sentinel NetLab - Rule-Based Detection Engine
JSON-configurable rules with Python evaluator for WIDS alerts.
"""

import re
import json
import logging
import operator
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional
from enum import Enum

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


@dataclass
class MitreAttack:
    """MITRE ATT&CK mapping"""
    technique_id: str
    technique_name: str
    tactic: str
    url: str = ""
    
    def __post_init__(self):
        if not self.url:
            self.url = f"https://attack.mitre.org/techniques/{self.technique_id.replace('.', '/')}/"


@dataclass
class Evidence:
    """Evidence item for an alert"""
    type: str  # frame, network, metric, correlation
    timestamp: str
    data: Dict[str, Any]
    description: str = ""


@dataclass
class Alert:
    """Security alert with evidence"""
    alert_id: str
    timestamp: str
    rule_id: str
    rule_name: str
    severity: Severity
    status: AlertStatus
    bssid: Optional[str]
    ssid: Optional[str]
    sensor_id: str
    description: str
    evidence: List[Evidence] = field(default_factory=list)
    mitre_attack: Optional[MitreAttack] = None
    score: float = 0.0
    
    def to_dict(self) -> Dict:
        result = asdict(self)
        result['severity'] = self.severity.value
        result['status'] = self.status.value
        result['evidence'] = [asdict(e) for e in self.evidence]
        result['mitre_attack'] = asdict(self.mitre_attack) if self.mitre_attack else None
        return result


@dataclass
class DetectionRule:
    """Rule configuration for detection"""
    rule_id: str
    name: str
    description: str
    severity: Severity
    enabled: bool = True
    
    # Conditions (all must match for rule to fire)
    conditions: List[Dict[str, Any]] = field(default_factory=list)
    
    # Thresholds
    threshold: Optional[Dict[str, Any]] = None
    
    # Time window for aggregation
    window_seconds: int = 0
    
    # MITRE mapping
    mitre_technique_id: str = ""
    mitre_technique_name: str = ""
    mitre_tactic: str = ""
    
    # Rate limiting
    cooldown_seconds: int = 300
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'DetectionRule':
        return cls(
            rule_id=data['rule_id'],
            name=data['name'],
            description=data.get('description', ''),
            severity=Severity(data.get('severity', 'medium')),
            enabled=data.get('enabled', True),
            conditions=data.get('conditions', []),
            threshold=data.get('threshold'),
            window_seconds=data.get('window_seconds', 0),
            mitre_technique_id=data.get('mitre_technique_id', ''),
            mitre_technique_name=data.get('mitre_technique_name', ''),
            mitre_tactic=data.get('mitre_tactic', ''),
            cooldown_seconds=data.get('cooldown_seconds', 300)
        )


class ConditionEvaluator:
    """Evaluate rule conditions against data"""
    
    OPERATORS = {
        'eq': operator.eq,
        '==': operator.eq,
        'ne': operator.ne,
        '!=': operator.ne,
        'gt': operator.gt,
        '>': operator.gt,
        'gte': operator.ge,
        '>=': operator.ge,
        'lt': operator.lt,
        '<': operator.lt,
        'lte': operator.le,
        '<=': operator.le,
        'in': lambda a, b: a in b,
        'not_in': lambda a, b: a not in b,
        'contains': lambda a, b: b in a if a else False,
        'regex': lambda a, b: bool(re.search(b, str(a))) if a else False,
        'exists': lambda a, b: a is not None if b else a is None,
    }
    
    def evaluate(self, condition: Dict, data: Dict) -> bool:
        """Evaluate a single condition against data"""
        field = condition.get('field')
        op = condition.get('op', 'eq')
        value = condition.get('value')
        
        # Get field value from data (supports nested fields with dot notation)
        actual = self._get_field(data, field)
        
        # Get operator function
        op_func = self.OPERATORS.get(op)
        if not op_func:
            logger.warning(f"Unknown operator: {op}")
            return False
        
        try:
            return op_func(actual, value)
        except (TypeError, ValueError) as e:
            logger.debug(f"Condition evaluation error: {e}")
            return False
    
    def evaluate_all(self, conditions: List[Dict], data: Dict) -> bool:
        """Evaluate all conditions (AND logic)"""
        if not conditions:
            return False
        return all(self.evaluate(c, data) for c in conditions)
    
    def _get_field(self, data: Dict, field: str) -> Any:
        """Get nested field value using dot notation"""
        if not field:
            return None
        
        parts = field.split('.')
        value = data
        
        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
            else:
                return None
        
        return value


class RuleEngine:
    """Rule-based detection engine"""
    
    def __init__(self, rules_path: Optional[Path] = None):
        self.rules: Dict[str, DetectionRule] = {}
        self.evaluator = ConditionEvaluator()
        self.last_fired: Dict[str, datetime] = {}  # For cooldown
        self.alert_count = 0
        
        if rules_path:
            self.load_rules(rules_path)
    
    def load_rules(self, path: Path):
        """Load rules from JSON file"""
        with open(path, 'r') as f:
            data = json.load(f)
        
        for rule_data in data.get('rules', []):
            rule = DetectionRule.from_dict(rule_data)
            self.rules[rule.rule_id] = rule
            logger.info(f"Loaded rule: {rule.rule_id} - {rule.name}")
        
        logger.info(f"Loaded {len(self.rules)} detection rules")
    
    def add_rule(self, rule: DetectionRule):
        """Add a rule programmatically"""
        self.rules[rule.rule_id] = rule
    
    def evaluate(self, data: Dict, sensor_id: str = "") -> List[Alert]:
        """Evaluate all rules against data, return triggered alerts"""
        alerts = []
        
        for rule_id, rule in self.rules.items():
            if not rule.enabled:
                continue
            
            # Check cooldown
            if self._in_cooldown(rule_id, rule.cooldown_seconds):
                continue
            
            # Evaluate conditions
            if self.evaluator.evaluate_all(rule.conditions, data):
                alert = self._create_alert(rule, data, sensor_id)
                alerts.append(alert)
                self.last_fired[rule_id] = datetime.now(timezone.utc)
                logger.info(f"Alert: [{rule.severity.value.upper()}] {rule.name}")
        
        return alerts
    
    def _in_cooldown(self, rule_id: str, cooldown_seconds: int) -> bool:
        """Check if rule is in cooldown period"""
        if rule_id not in self.last_fired:
            return False
        
        elapsed = (datetime.now(timezone.utc) - self.last_fired[rule_id]).total_seconds()
        return elapsed < cooldown_seconds
    
    def _create_alert(self, rule: DetectionRule, data: Dict, sensor_id: str) -> Alert:
        """Create alert from triggered rule"""
        self.alert_count += 1
        alert_id = f"ALT-{datetime.now().strftime('%Y%m%d%H%M%S')}-{self.alert_count:04d}"
        
        # Build evidence
        evidence = [
            Evidence(
                type="trigger_data",
                timestamp=datetime.now(timezone.utc).isoformat(),
                data=data,
                description="Data that triggered the alert"
            )
        ]
        
        # Build MITRE mapping
        mitre = None
        if rule.mitre_technique_id:
            mitre = MitreAttack(
                technique_id=rule.mitre_technique_id,
                technique_name=rule.mitre_technique_name,
                tactic=rule.mitre_tactic
            )
        
        return Alert(
            alert_id=alert_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            rule_id=rule.rule_id,
            rule_name=rule.name,
            severity=rule.severity,
            status=AlertStatus.OPEN,
            bssid=data.get('bssid'),
            ssid=data.get('ssid'),
            sensor_id=sensor_id,
            description=rule.description,
            evidence=evidence,
            mitre_attack=mitre
        )


# =============================================================================
# DEFAULT DETECTION RULES
# =============================================================================

DEFAULT_RULES = {
    "rules": [
        {
            "rule_id": "WIDS-001",
            "name": "Open Network Detected",
            "description": "Unencrypted wireless network detected. Open networks expose traffic to eavesdropping.",
            "severity": "high",
            "conditions": [
                {"field": "security", "op": "eq", "value": "Open"}
            ],
            "mitre_technique_id": "T1557",
            "mitre_technique_name": "Adversary-in-the-Middle",
            "mitre_tactic": "Credential Access",
            "cooldown_seconds": 3600
        },
        {
            "rule_id": "WIDS-002",
            "name": "WEP Encryption Detected",
            "description": "Network using deprecated WEP encryption which can be cracked in minutes.",
            "severity": "critical",
            "conditions": [
                {"field": "security", "op": "contains", "value": "WEP"}
            ],
            "mitre_technique_id": "T1040",
            "mitre_technique_name": "Network Sniffing",
            "mitre_tactic": "Credential Access",
            "cooldown_seconds": 3600
        },
        {
            "rule_id": "WIDS-003",
            "name": "WPS Enabled",
            "description": "WPS is enabled, vulnerable to PIN brute force attacks (Reaver/Bully).",
            "severity": "medium",
            "conditions": [
                {"field": "capabilities.wps", "op": "eq", "value": True}
            ],
            "mitre_technique_id": "T1110",
            "mitre_technique_name": "Brute Force",
            "mitre_tactic": "Credential Access",
            "cooldown_seconds": 3600
        },
        {
            "rule_id": "WIDS-004",
            "name": "Suspicious SSID Pattern",
            "description": "SSID matches common phishing/rogue AP patterns.",
            "severity": "medium",
            "conditions": [
                {"field": "ssid", "op": "regex", "value": "(?i)(free|guest|xfinity|starbucks)"}
            ],
            "mitre_technique_id": "T1557.002",
            "mitre_technique_name": "ARP Cache Poisoning",
            "mitre_tactic": "Credential Access",
            "cooldown_seconds": 1800
        },
        {
            "rule_id": "WIDS-005",
            "name": "Unusually Strong Signal",
            "description": "Signal strength indicates AP may be very close or spoofed (potential rogue AP).",
            "severity": "low",
            "conditions": [
                {"field": "rssi_dbm", "op": ">=", "value": -30}
            ],
            "mitre_technique_id": "T1200",
            "mitre_technique_name": "Hardware Additions",
            "mitre_tactic": "Initial Access",
            "cooldown_seconds": 900
        }
    ]
}


def create_default_rules_file(path: Path):
    """Create default rules file"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w') as f:
        json.dump(DEFAULT_RULES, f, indent=2)
    logger.info(f"Created default rules file: {path}")


# =============================================================================
# CLI
# =============================================================================

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Rule Engine CLI')
    parser.add_argument('--rules', type=Path, help='Path to rules JSON file')
    parser.add_argument('--create-default', type=Path, help='Create default rules file')
    parser.add_argument('--test', action='store_true', help='Run test with sample data')
    
    args = parser.parse_args()
    
    if args.create_default:
        create_default_rules_file(args.create_default)
        return
    
    # Initialize engine
    engine = RuleEngine()
    
    if args.rules:
        engine.load_rules(args.rules)
    else:
        # Load default rules
        for rule_data in DEFAULT_RULES['rules']:
            engine.add_rule(DetectionRule.from_dict(rule_data))
    
    if args.test:
        # Test with sample data
        test_data = [
            {"bssid": "AA:BB:CC:11:22:33", "ssid": "OpenCafe", "security": "Open", "rssi_dbm": -50},
            {"bssid": "AA:BB:CC:44:55:66", "ssid": "SecureNet", "security": "WPA2", "rssi_dbm": -65},
            {"bssid": "AA:BB:CC:77:88:99", "ssid": "OldRouter", "security": "WEP", "rssi_dbm": -70},
            {"bssid": "AA:BB:CC:AA:BB:CC", "ssid": "FREE_STARBUCKS_WIFI", "security": "Open", "rssi_dbm": -25},
        ]
        
        print("\n" + "="*60)
        print("RULE ENGINE TEST")
        print("="*60)
        
        for data in test_data:
            print(f"\nTesting: {data.get('ssid')} ({data.get('security')})")
            alerts = engine.evaluate(data, sensor_id="test-sensor")
            for alert in alerts:
                print(f"  ⚠️  [{alert.severity.value.upper()}] {alert.rule_name}")
                if alert.mitre_attack:
                    print(f"      MITRE: {alert.mitre_attack.technique_id} - {alert.mitre_attack.technique_name}")


if __name__ == '__main__':
    main()
