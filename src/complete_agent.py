#!/usr/bin/env python3
"""
Complete Autonomous Network Security AI Agent
Integrates live capture, threat detection, decision making, and autonomous response
"""

import time
import threading
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import os
import signal
import sys
from dataclasses import dataclass

try:
    # Try importing from src module (when called from dashboard)
    from src.autonomous_agent import NetworkSecurityAgent, AgentAction, ActionType, ThreatLevel
    from src.live_capture import LiveNetworkCapture, LiveNetworkEvent
    from src.threat_detector import AIThreatDetector
except ImportError:
    # Fallback to direct imports (when run from src directory)
    from autonomous_agent import NetworkSecurityAgent, AgentAction, ActionType, ThreatLevel
    from live_capture import LiveNetworkCapture, LiveNetworkEvent
    from threat_detector import AIThreatDetector

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

class AutonomousNetworkAgent:
    """Complete autonomous network security agent with AI decision making"""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.logger = logging.getLogger(self.__class__.__name__)

        # Initialize components
        self.network_capture = LiveNetworkCapture(
            interface=self.config.get('interface'),
            capture_filter=self.config.get('capture_filter', 'ip')
        )

        self.threat_detector = AIThreatDetector(
            openai_api_key=self.config.get('openai_api_key')
        )

        self.security_agent = NetworkSecurityAgent(self.config, self.network_capture)

        # Agent state
        self.is_running = False
        self.start_time = None

        # Metrics and logging
        self.session_stats = {
            'threats_detected': 0,
            'actions_taken': 0,
            'false_positives': 0,
            'total_events_processed': 0,
            'critical_threats': 0,
            'high_threats': 0,
            'medium_threats': 0,
            'low_threats': 0
        }

        # Connect network events to threat analysis
        self.network_capture.add_event_callback(self._on_network_event)

        # Set up graceful shutdown (only in main thread)
        try:
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
        except ValueError:
            # Signal handlers can only be set in the main thread
            # This is expected when running in Streamlit or other frameworks
            self.logger.debug("Signal handlers not set (not in main thread)")

    def start_autonomous_operation(self, duration: Optional[int] = None, simulation: bool = False):
        """Start the complete autonomous agent operation"""

        if self.is_running:
            self.logger.warning("Agent is already running")
            return

        self.logger.info("🤖 Starting Autonomous Network Security Agent")
        self.logger.info("=" * 60)

        try:
            self.is_running = True
            self.start_time = datetime.now()

            # Start network capture
            if simulation:
                self.logger.info("🧪 Starting in SIMULATION mode")
                # Start simulation in a separate thread
                sim_thread = threading.Thread(
                    target=self.network_capture.simulate_network_events,
                    args=(duration or 120,),  # Default 2 minutes simulation
                    daemon=True
                )
                sim_thread.start()
            else:
                self.logger.info("📡 Starting live network capture")
                self.network_capture.start_capture()

            # Start the core security agent with direct network capture access
            self.security_agent.start_autonomous_operation()

            self.logger.info("✅ All systems operational - Agent is now autonomous")
            self.logger.info("🎯 Agent Goals:")
            for goal, target in self.security_agent.goals.items():
                self.logger.info(f"   - {goal}: {target}")

            # Main operation loop
            if duration:
                self.logger.info(f"⏱️  Running for {duration} seconds")
                time.sleep(duration)
                self.stop_autonomous_operation()
            else:
                self.logger.info("🔄 Running indefinitely (Ctrl+C to stop)")
                while self.is_running:
                    time.sleep(1)

        except KeyboardInterrupt:
            self.logger.info("\n🛑 Received stop signal")
        except Exception as e:
            self.logger.error(f"❌ Agent error: {e}")
        finally:
            if self.is_running:
                self.stop_autonomous_operation()

    def stop_autonomous_operation(self):
        """Stop all agent operations"""
        if not self.is_running:
            return

        self.logger.info("🛑 Stopping Autonomous Network Security Agent")

        self.is_running = False

        # Stop components
        self.network_capture.stop_capture()
        self.security_agent.stop_autonomous_operation()

        # Final report
        self._generate_session_report()

        self.logger.info("✅ Agent stopped successfully")

    def _on_network_event(self, event: LiveNetworkEvent):
        """Handle incoming network events from live capture"""
        self.session_stats['total_events_processed'] += 1

        # Log high-level event info (reduce noise in logs)
        if self.session_stats['total_events_processed'] % 100 == 0:
            self.logger.debug(f"📊 Processed {self.session_stats['total_events_processed']} events")


    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        self.logger.info(f"\n🛑 Received signal {signum}")
        self.stop_autonomous_operation()
        # Only exit if we're in the main thread
        try:
            sys.exit(0)
        except SystemExit:
            pass

    def _generate_session_report(self):
        """Generate a final session report"""
        if not self.start_time:
            return

        duration = datetime.now() - self.start_time
        capture_stats = self.network_capture.get_capture_stats()
        agent_status = self.security_agent.get_agent_status()

        self.logger.info("📊 AUTONOMOUS AGENT SESSION REPORT")
        self.logger.info("=" * 50)
        self.logger.info(f"Duration: {duration}")
        self.logger.info(f"Events Processed: {self.session_stats['total_events_processed']}")
        self.logger.info(f"Packets Captured: {capture_stats.get('packets_captured', 0)}")
        self.logger.info(f"Actions Taken: {agent_status['metrics']['actions_taken']}")
        self.logger.info(f"Threats Detected: {agent_status['metrics']['threats_detected']}")

        # Top protocols and IPs
        top_protocols = capture_stats.get('top_protocols', {})
        if top_protocols:
            self.logger.info(f"Top Protocols: {top_protocols}")

        top_sources = capture_stats.get('top_sources', {})
        if top_sources:
            self.logger.info(f"Top Source IPs: {list(top_sources.keys())[:5]}")

        self.logger.info("=" * 50)

    def get_live_status(self) -> Dict[str, Any]:
        """Get current live status of all agent components"""
        return {
            'agent_running': self.is_running,
            'uptime': str(datetime.now() - self.start_time) if self.start_time else None,
            'session_stats': self.session_stats,
            'network_capture': self.network_capture.get_capture_stats(),
            'security_agent': self.security_agent.get_agent_status(),
            'threat_detector': self.threat_detector.get_detection_stats()
        }

def main():
    """Main entry point for autonomous agent"""
    import argparse

    parser = argparse.ArgumentParser(description='Autonomous Network Security AI Agent')
    parser.add_argument('--interface', help='Network interface to monitor')
    parser.add_argument('--duration', type=int, help='Run duration in seconds')
    parser.add_argument('--simulation', action='store_true', help='Run in simulation mode')
    parser.add_argument('--config', help='Path to configuration file')

    args = parser.parse_args()

    # Load configuration
    config = {
        'interface': args.interface,
        'monitoring_interval': 5,  # 5 second monitoring cycles
        'openai_api_key': os.getenv('OPENAI_API_KEY')
    }

    if args.config:
        # Load from config file if provided
        import json
        try:
            with open(args.config, 'r') as f:
                config.update(json.load(f))
        except Exception as e:
            print(f"Warning: Could not load config file: {e}")

    # Create and start agent
    agent = AutonomousNetworkAgent(config)

    print("🤖 Autonomous Network Security AI Agent")
    print("=====================================")
    print(f"Interface: {config.get('interface', 'auto-detect')}")
    print(f"AI Analysis: {'Enabled' if config.get('openai_api_key') else 'Disabled (no API key)'}")
    print(f"Mode: {'Simulation' if args.simulation else 'Live Capture'}")
    print()

    try:
        agent.start_autonomous_operation(
            duration=args.duration,
            simulation=args.simulation
        )
    except KeyboardInterrupt:
        print("\n🛑 Stopping agent...")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()