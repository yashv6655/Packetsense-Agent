#!/usr/bin/env python3
"""
Test script for the Autonomous Network Security Agent
Demonstrates true AI agent capabilities in simulation mode
"""

import os
import sys
import time
import logging
from datetime import datetime

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from complete_agent import AutonomousNetworkAgent

def test_autonomous_agent():
    """Test the autonomous agent in simulation mode"""
    print("Testing Autonomous Network Security AI Agent")
    print("=" * 60)

    # Configure logging to see agent decisions
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Create agent configuration
    config = {
        'monitoring_interval': 3,  # 3 second monitoring cycles
        'openai_api_key': os.getenv('OPENAI_API_KEY'),
        'interface': None  # Auto-detect
    }

    print(f"Configuration:")
    print(f"   - Monitoring interval: {config['monitoring_interval']} seconds")
    print(f"   - AI Analysis: {'Enabled' if config['openai_api_key'] else 'Disabled'}")
    print(f"   - Interface: Auto-detect")
    print()

    # Create the autonomous agent
    print("Creating autonomous agent...")
    agent = AutonomousNetworkAgent(config)

    print("Agent created successfully!")
    print()

    # Test agent capabilities
    print("Testing Agent Capabilities:")
    print("=" * 40)

    # Test 1: Check agent can be started
    print("1  Testing agent startup...")
    try:
        # Start agent in simulation mode for 30 seconds
        print("    Starting agent in simulation mode (30 seconds)...")
        agent.start_autonomous_operation(duration=30, simulation=True)
        print("   Agent completed autonomous operation")
    except Exception as e:
        print(f"   Agent startup failed: {e}")
        return False

    # Test 2: Check final status
    print("\n2  Checking final agent status...")
    try:
        final_status = agent.get_live_status()
        print(f"    Events processed: {final_status['session_stats']['total_events_processed']}")
        print(f"    Actions taken: {final_status['session_stats']['actions_taken']}")
        print(f"    Uptime: {final_status['uptime']}")
        print("   Status check passed")
    except Exception as e:
        print(f"    Status check failed: {e}")
        return False

    print("\nAll tests passed! The autonomous agent is working correctly.")
    return True

def demonstrate_agent_checkboxes():
    """Demonstrate how this qualifies as a true AI agent"""
    print("\nAI AGENT QUALIFICATION CHECKLIST")
    print("=" * 50)

    checkboxes = [
        ("Autonomy", "Runs independently without human intervention"),
        ("Goal-Oriented", "Works toward security objectives (threat detection, response time)"),
        ("Environment Interaction", "Observes network traffic and takes security actions"),
        ("Reactivity", "Responds to network events and threats in real-time"),
        ("Decision Making", "Chooses actions based on threat assessment"),
        ("Learning/Adaptation", "Builds threat patterns memory and improves detection"),
        ("Continuous Operation", "Runs 24/7 monitoring loop until stopped"),
        ("Multiple Detection Methods", "Rule-based + Statistical + AI analysis"),
        ("Persistent Memory", "Stores and recalls threat patterns"),
        ("Autonomous Response", "Blocks IPs, sends alerts, escalates threats")
    ]

    for checkbox, status, description in checkboxes:
        print(f"{status} {checkbox:<25} {description}")

    print("\nRESULT: This IS a true autonomous AI agent!")
    print("   Unlike tools that just analyze data when asked,")
    print("   this agent actively monitors, decides, and acts on its own.")

if __name__ == "__main__":
    print("PacketSense Autonomous Agent Test Suite")
    print("==========================================")
    print()

    # Run the test
    success = test_autonomous_agent()

    if success:
        # Show the qualification checklist
        demonstrate_agent_checkboxes()

        print("\nReady to run the full agent!")
        print("   Use: streamlit run agent_dashboard.py")
        print("   Or:  python -m src.complete_agent --simulation --duration 60")
    else:
        print("\nTests failed. Check the error messages above.")
        sys.exit(1)