#!/usr/bin/env python3
"""
Test script for threat detection capabilities
Tests the AI agent with various simulated attack scenarios
"""

import os
import sys
import time
import logging
from datetime import datetime

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from complete_agent import AutonomousNetworkAgent
from enhanced_live_capture import EnhancedLiveCapture
from threat_simulator import AttackType

def test_threat_detection():
    """Test the agent's ability to detect various types of threats"""
    print("🎯 PacketSense Threat Detection Test")
    print("=" * 60)
    
    # Configure logging to see agent decisions
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create agent configuration
    config = {
        'monitoring_interval': 2,  # 2 second monitoring cycles for faster testing
        'openai_api_key': os.getenv('OPENAI_API_KEY'),
        'interface': None,  # Will use simulation
        'action_executor': {
            'dry_run': True,  # Safe testing mode
            'enable_ip_blocking': False,  # No real blocking
            'enable_notifications': True
        }
    }
    
    print(f"Configuration:")
    print(f"   - Monitoring interval: {config['monitoring_interval']} seconds")
    print(f"   - AI Analysis: {'Enabled' if config['openai_api_key'] else 'Disabled'}")
    print(f"   - Dry run mode: {config['action_executor']['dry_run']}")
    print()
    
    # Create the autonomous agent
    print("Creating autonomous agent...")
    agent = AutonomousNetworkAgent(config)
    
    # Replace the network capture with enhanced version
    agent.network_capture = EnhancedLiveCapture()
    agent.security_agent.network_capture = agent.network_capture
    
    print("Agent created successfully!")
    print()
    
    # Test scenarios
    test_scenarios = [
        {
            'name': 'Port Scan Attack',
            'attack_types': [AttackType.PORT_SCAN],
            'duration': 45,
            'description': 'Tests detection of port scanning behavior'
        },
        {
            'name': 'DoS Attack',
            'attack_types': [AttackType.DOS_ATTACK],
            'duration': 30,
            'description': 'Tests detection of denial-of-service attacks'
        },
        {
            'name': 'Data Exfiltration',
            'attack_types': [AttackType.DATA_EXFILTRATION],
            'duration': 40,
            'description': 'Tests detection of large data transfers'
        },
        {
            'name': 'DNS Tunneling',
            'attack_types': [AttackType.DNS_TUNNELING],
            'duration': 35,
            'description': 'Tests detection of DNS-based data exfiltration'
        },
        {
            'name': 'Lateral Movement',
            'attack_types': [AttackType.LATERAL_MOVEMENT],
            'duration': 40,
            'description': 'Tests detection of internal network scanning'
        },
        {
            'name': 'Mixed Attack Scenario',
            'attack_types': [
                AttackType.PORT_SCAN,
                AttackType.DOS_ATTACK,
                AttackType.DATA_EXFILTRATION
            ],
            'duration': 60,
            'description': 'Tests detection of multiple simultaneous attacks'
        }
    ]
    
    print("🎯 Starting Threat Detection Tests")
    print("=" * 50)
    
    for i, scenario in enumerate(test_scenarios, 1):
        print(f"\n{i}. {scenario['name']}")
        print(f"   Description: {scenario['description']}")
        print(f"   Duration: {scenario['duration']} seconds")
        print(f"   Attack types: {[t.value for t in scenario['attack_types']]}")
        print()
        
        try:
            # Start the agent
            print("   Starting agent...")
            agent.start_autonomous_operation(
                duration=scenario['duration'],
                simulation=True
            )
            
            # Get final status
            final_status = agent.get_live_status()
            print(f"   ✅ Test completed")
            print(f"   Events processed: {final_status['session_stats']['total_events_processed']}")
            print(f"   Actions taken: {final_status['security_agent']['metrics']['actions_taken']}")
            print(f"   Threats detected: {final_status['security_agent']['metrics']['threats_detected']}")
            
            # Check if agent detected the threat
            if final_status['security_agent']['metrics']['actions_taken'] > 0:
                print(f"   🎯 SUCCESS: Agent detected and responded to threats!")
            else:
                print(f"   ⚠️  WARNING: Agent did not take any actions")
            
        except Exception as e:
            print(f"   ❌ Test failed: {e}")
        
        print("   " + "-" * 40)
        
        # Brief pause between tests
        time.sleep(5)
    
    print("\n🎯 All threat detection tests completed!")
    print("\nSummary:")
    print("- The agent should have detected various attack patterns")
    print("- Check the logs above for specific threat assessments")
    print("- Actions taken indicate successful threat detection")
    print("- Use the dashboard for real-time monitoring: streamlit run agent_dashboard.py")

def test_specific_attack(attack_type: AttackType, duration: int = 60):
    """Test a specific attack type"""
    print(f"🎯 Testing {attack_type.value} detection")
    print("=" * 40)
    
    config = {
        'monitoring_interval': 2,
        'openai_api_key': os.getenv('OPENAI_API_KEY'),
        'interface': None,
        'action_executor': {
            'dry_run': True,
            'enable_ip_blocking': False,
            'enable_notifications': True
        }
    }
    
    agent = AutonomousNetworkAgent(config)
    agent.network_capture = EnhancedLiveCapture()
    agent.security_agent.network_capture = agent.network_capture
    
    print(f"Starting {attack_type.value} simulation for {duration} seconds...")
    
    try:
        agent.start_autonomous_operation(duration=duration, simulation=True)
        
        final_status = agent.get_live_status()
        print(f"\nResults:")
        print(f"  Events processed: {final_status['session_stats']['total_events_processed']}")
        print(f"  Actions taken: {final_status['security_agent']['metrics']['actions_taken']}")
        print(f"  Threats detected: {final_status['security_agent']['metrics']['threats_detected']}")
        
        if final_status['security_agent']['metrics']['actions_taken'] > 0:
            print(f"  🎯 SUCCESS: {attack_type.value} was detected!")
        else:
            print(f"  ⚠️  {attack_type.value} was not detected")
            
    except Exception as e:
        print(f"❌ Test failed: {e}")

def main():
    """Main test function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Test PacketSense threat detection')
    parser.add_argument('--attack', help='Specific attack type to test', 
                       choices=[t.value for t in AttackType])
    parser.add_argument('--duration', type=int, default=60, 
                       help='Test duration in seconds')
    parser.add_argument('--all', action='store_true', 
                       help='Run all attack scenarios')
    
    args = parser.parse_args()
    
    if args.attack:
        attack_type = AttackType(args.attack)
        test_specific_attack(attack_type, args.duration)
    elif args.all:
        test_threat_detection()
    else:
        print("PacketSense Threat Detection Test")
        print("Usage:")
        print("  python test_threat_detection.py --all                    # Run all tests")
        print("  python test_threat_detection.py --attack port_scan       # Test specific attack")
        print("  python test_threat_detection.py --attack dos_attack --duration 30")
        print()
        print("Available attack types:")
        for attack_type in AttackType:
            print(f"  - {attack_type.value}")

if __name__ == "__main__":
    main()
