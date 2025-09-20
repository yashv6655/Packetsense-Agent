#!/usr/bin/env python3
"""
Simple threat test that directly tests the agent's threat detection capabilities
"""

import os
import sys
import time
import logging
import random
from datetime import datetime

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.autonomous_agent import NetworkSecurityAgent, NetworkEvent, ThreatLevel
from src.threat_detector import AIThreatDetector
from src.action_executor import ActionExecutor

def create_port_scan_events():
    """Create simulated port scan events"""
    events = []
    attacker_ip = "192.168.1.200"
    target_ip = "192.168.1.100"
    
    # Simulate rapid port scanning
    ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1433, 3389]
    
    for i, port in enumerate(ports):
        event = NetworkEvent(
            timestamp=datetime.now(),
            source_ip=attacker_ip,
            dest_ip=target_ip,
            protocol="TCP",
            size=64,
            suspicious_score=0.0,
            event_data={'port': port}
        )
        events.append(event)
        time.sleep(0.1)  # Rapid scanning
    
    return events

def create_dos_attack_events():
    """Create simulated DoS attack events"""
    events = []
    attacker_ip = "10.0.0.100"
    target_ip = "192.168.1.1"
    
    # Simulate high volume of packets
    for i in range(150):  # High packet count
        event = NetworkEvent(
            timestamp=datetime.now(),
            source_ip=attacker_ip,
            dest_ip=target_ip,
            protocol="TCP",
            size=random.randint(64, 1500),
            suspicious_score=0.0,
            event_data={'port': 80}
        )
        events.append(event)
        time.sleep(0.01)  # Very fast packet rate
    
    return events

def create_data_exfiltration_events():
    """Create simulated data exfiltration events"""
    events = []
    internal_ip = "192.168.1.150"
    external_ip = "203.0.113.50"
    
    # Simulate large data transfers
    for i in range(50):
        event = NetworkEvent(
            timestamp=datetime.now(),
            source_ip=internal_ip,
            dest_ip=external_ip,
            protocol="TCP",
            size=random.randint(10000, 50000),  # Large packets
            suspicious_score=0.0,
            event_data={'port': 443}
        )
        events.append(event)
        time.sleep(0.2)
    
    return events

def test_threat_detection():
    """Test the agent's threat detection capabilities"""
    print("🎯 Simple Threat Detection Test")
    print("=" * 50)
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create agent components
    config = {
        'monitoring_interval': 2,
        'openai_api_key': os.getenv('OPENAI_API_KEY'),
        'action_executor': {
            'dry_run': True,
            'enable_ip_blocking': False,
            'enable_notifications': True
        }
    }
    
    # Create the security agent
    agent = NetworkSecurityAgent(config)
    
    print("Agent created successfully!")
    print()
    
    # Test scenarios
    test_scenarios = [
        {
            'name': 'Port Scan Attack',
            'create_events': create_port_scan_events,
            'expected_threat_level': ThreatLevel.HIGH
        },
        {
            'name': 'DoS Attack',
            'create_events': create_dos_attack_events,
            'expected_threat_level': ThreatLevel.CRITICAL
        },
        {
            'name': 'Data Exfiltration',
            'create_events': create_data_exfiltration_events,
            'expected_threat_level': ThreatLevel.HIGH
        }
    ]
    
    for i, scenario in enumerate(test_scenarios, 1):
        print(f"{i}. Testing {scenario['name']}")
        print("-" * 30)
        
        try:
            # Create attack events
            print("   Creating attack events...")
            events = scenario['create_events']()
            print(f"   Created {len(events)} events")
            
            # Test threat assessment
            print("   Assessing threats...")
            assessment = agent._assess_threats(events)
            
            print(f"   Threat Level: {assessment.threat_level.name}")
            print(f"   Confidence: {assessment.confidence:.2f}")
            print(f"   Indicators: {len(assessment.indicators)}")
            
            if assessment.indicators:
                print("   Threat Indicators:")
                for indicator in assessment.indicators[:3]:  # Show first 3
                    print(f"     - {indicator}")
            
            # Test action decision
            print("   Deciding actions...")
            actions = agent._decide_actions(assessment, events)
            
            print(f"   Actions decided: {len(actions)}")
            for action in actions:
                print(f"     - {action.action_type.value}: {action.reason}")
            
            # Check if threat was detected
            if assessment.threat_level != ThreatLevel.LOW:
                print(f"   🎯 SUCCESS: {scenario['name']} detected!")
            else:
                print(f"   ⚠️  WARNING: {scenario['name']} not detected")
            
        except Exception as e:
            print(f"   ❌ Test failed: {e}")
        
        print()
        time.sleep(2)  # Brief pause between tests
    
    print("🎯 All tests completed!")

def test_specific_attack(attack_type):
    """Test a specific attack type"""
    print(f"🎯 Testing {attack_type} detection")
    print("=" * 40)
    
    config = {
        'monitoring_interval': 2,
        'openai_api_key': os.getenv('OPENAI_API_KEY'),
        'action_executor': {
            'dry_run': True,
            'enable_ip_blocking': False,
            'enable_notifications': True
        }
    }
    
    agent = NetworkSecurityAgent(config)
    
    # Create events based on attack type
    if attack_type == 'port_scan':
        events = create_port_scan_events()
    elif attack_type == 'dos':
        events = create_dos_attack_events()
    elif attack_type == 'exfil':
        events = create_data_exfiltration_events()
    else:
        print(f"Unknown attack type: {attack_type}")
        return
    
    print(f"Created {len(events)} {attack_type} events")
    
    # Test threat assessment
    assessment = agent._assess_threats(events)
    
    print(f"\nResults:")
    print(f"  Threat Level: {assessment.threat_level.name}")
    print(f"  Confidence: {assessment.confidence:.2f}")
    print(f"  Indicators: {len(assessment.indicators)}")
    
    if assessment.indicators:
        print("  Threat Indicators:")
        for indicator in assessment.indicators:
            print(f"    - {indicator}")
    
    # Test actions
    actions = agent._decide_actions(assessment, events)
    print(f"  Actions: {len(actions)}")
    for action in actions:
        print(f"    - {action.action_type.value}")
    
    if assessment.threat_level != ThreatLevel.LOW:
        print(f"  🎯 SUCCESS: {attack_type} was detected!")
    else:
        print(f"  ⚠️  {attack_type} was not detected")

def main():
    """Main function"""
    import argparse
    import random
    
    parser = argparse.ArgumentParser(description='Simple threat detection test')
    parser.add_argument('--attack', choices=['port_scan', 'dos', 'exfil'],
                       help='Specific attack type to test')
    parser.add_argument('--all', action='store_true',
                       help='Run all attack tests')
    
    args = parser.parse_args()
    
    if args.attack:
        test_specific_attack(args.attack)
    elif args.all:
        test_threat_detection()
    else:
        print("Simple Threat Detection Test")
        print("Usage:")
        print("  python simple_threat_test.py --all                    # Run all tests")
        print("  python simple_threat_test.py --attack port_scan       # Test specific attack")
        print()
        print("Available attack types:")
        print("  - port_scan: Port scanning attack")
        print("  - dos: Denial of service attack")
        print("  - exfil: Data exfiltration attack")

if __name__ == "__main__":
    main()
