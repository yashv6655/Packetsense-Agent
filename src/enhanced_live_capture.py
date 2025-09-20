#!/usr/bin/env python3
"""
Enhanced Live Capture with Threat Simulation
"""

import time
import threading
from datetime import datetime
from typing import List, Dict, Any, Optional, Callable
import logging

try:
    from src.live_capture import LiveNetworkCapture, LiveNetworkEvent
    from src.threat_simulator import ThreatSimulator, AttackType
except ImportError:
    from live_capture import LiveNetworkCapture, LiveNetworkEvent
    from threat_simulator import ThreatSimulator, AttackType

class EnhancedLiveCapture(LiveNetworkCapture):
    """Enhanced live capture with threat simulation capabilities"""

    def __init__(self, interface: str = None, capture_filter: str = None):
        super().__init__(interface, capture_filter)
        self.threat_simulator = ThreatSimulator(callback_func=self._on_simulated_event)
        self.simulation_mode = False
        self.attack_types = None

    def simulate_network_events_with_threats(self, duration: int = 60, attack_types: List[AttackType] = None):
        """Simulate network events including realistic attack patterns"""
        self.logger.info(f"🎯 Starting enhanced network simulation with threats for {duration} seconds")
        
        if attack_types is None:
            # Default to all attack types
            attack_types = [
                AttackType.PORT_SCAN,
                AttackType.DOS_ATTACK,
                AttackType.DATA_EXFILTRATION,
                AttackType.DNS_TUNNELING,
                AttackType.LATERAL_MOVEMENT
            ]
        
        self.attack_types = attack_types
        self.simulation_mode = True
        self.is_capturing = True
        self.stats['capture_start_time'] = datetime.now()

        # Start threat simulation in a separate thread
        self.simulation_thread = threading.Thread(
            target=self.threat_simulator.simulate_attack_sequence,
            args=(duration, attack_types),
            daemon=True
        )
        self.simulation_thread.start()

        self.logger.info("✅ Enhanced threat simulation started")

    def _on_simulated_event(self, event: LiveNetworkEvent):
        """Handle simulated events from threat simulator"""
        # Add to buffer
        self.event_buffer.append(event)
        
        # Notify all callbacks
        for callback in self.event_callbacks:
            try:
                callback(event)
            except Exception as e:
                self.logger.error(f"Error in event callback: {e}")

        # Update statistics
        self.stats['packets_captured'] += 1
        self.stats['events_processed'] += 1
        self.stats['protocols'][event.protocol] += 1
        self.stats['top_sources'][event.source_ip] += 1
        self.stats['top_destinations'][event.dest_ip] += 1

    def stop_capture(self):
        """Stop capture and simulation"""
        super().stop_capture()
        if hasattr(self, 'threat_simulator'):
            self.threat_simulator.stop_simulation()
        if hasattr(self, 'simulation_thread'):
            self.simulation_thread.join(timeout=5)

    def get_simulation_info(self) -> Dict[str, Any]:
        """Get information about current simulation"""
        if not self.simulation_mode:
            return {"simulation_mode": False}
        
        return {
            "simulation_mode": True,
            "attack_types": [t.value for t in self.attack_types] if self.attack_types else [],
            "available_scenarios": self.threat_simulator.get_available_scenarios()
        }
