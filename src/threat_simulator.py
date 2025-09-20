#!/usr/bin/env python3
"""
Threat Simulator - Generates realistic attack patterns for testing the AI agent
"""

import time
import random
import threading
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum
import logging

try:
    from src.live_capture import LiveNetworkEvent
except ImportError:
    from live_capture import LiveNetworkEvent

class AttackType(Enum):
    PORT_SCAN = "port_scan"
    DOS_ATTACK = "dos_attack"
    DATA_EXFILTRATION = "data_exfiltration"
    DNS_TUNNELING = "dns_tunneling"
    LATERAL_MOVEMENT = "lateral_movement"
    SUSPICIOUS_PROTOCOL = "suspicious_protocol"
    NORMAL_TRAFFIC = "normal_traffic"

@dataclass
class AttackScenario:
    attack_type: AttackType
    duration: int  # seconds
    intensity: float  # 0.0 to 1.0
    description: str

class ThreatSimulator:
    """Generates realistic network attack patterns for testing the AI agent"""

    def __init__(self, callback_func=None):
        self.callback_func = callback_func
        self.logger = logging.getLogger(self.__class__.__name__)
        self.is_running = False
        self.attack_thread = None
        
        # Attack scenarios
        self.scenarios = {
            AttackType.PORT_SCAN: AttackScenario(
                attack_type=AttackType.PORT_SCAN,
                duration=30,
                intensity=0.8,
                description="Simulates port scanning attack - multiple ports from single source"
            ),
            AttackType.DOS_ATTACK: AttackScenario(
                attack_type=AttackType.DOS_ATTACK,
                duration=20,
                intensity=0.9,
                description="Simulates DoS attack - high volume of packets"
            ),
            AttackType.DATA_EXFILTRATION: AttackScenario(
                attack_type=AttackType.DATA_EXFILTRATION,
                duration=45,
                intensity=0.7,
                description="Simulates data exfiltration - large outbound transfers"
            ),
            AttackType.DNS_TUNNELING: AttackScenario(
                attack_type=AttackType.DNS_TUNNELING,
                duration=60,
                intensity=0.6,
                description="Simulates DNS tunneling - excessive DNS queries"
            ),
            AttackType.LATERAL_MOVEMENT: AttackScenario(
                attack_type=AttackType.LATERAL_MOVEMENT,
                duration=40,
                intensity=0.8,
                description="Simulates lateral movement - internal network scanning"
            ),
            AttackType.SUSPICIOUS_PROTOCOL: AttackScenario(
                attack_type=AttackType.SUSPICIOUS_PROTOCOL,
                duration=25,
                intensity=0.5,
                description="Simulates suspicious protocol usage"
            )
        }

    def simulate_attack_sequence(self, duration: int = 300, attack_types: List[AttackType] = None):
        """Simulate a sequence of attacks over the specified duration"""
        if attack_types is None:
            attack_types = list(AttackType)
        
        self.logger.info(f"🎯 Starting attack simulation for {duration} seconds")
        self.logger.info(f"📋 Attack types: {[t.value for t in attack_types]}")
        
        self.is_running = True
        start_time = time.time()
        
        # Start with normal traffic
        self._simulate_normal_traffic(30)
        
        while self.is_running and (time.time() - start_time) < duration:
            # Choose random attack type
            attack_type = random.choice(attack_types)
            scenario = self.scenarios[attack_type]
            
            self.logger.warning(f"🚨 SIMULATING ATTACK: {attack_type.value.upper()}")
            self.logger.info(f"   Description: {scenario.description}")
            self.logger.info(f"   Duration: {scenario.duration}s, Intensity: {scenario.intensity}")
            
            # Simulate the attack
            self._simulate_attack(attack_type, scenario)
            
            # Brief pause between attacks
            time.sleep(random.uniform(10, 30))
            
            # Some normal traffic between attacks
            self._simulate_normal_traffic(random.randint(15, 45))
        
        self.is_running = False
        self.logger.info("🎯 Attack simulation completed")

    def _simulate_attack(self, attack_type: AttackType, scenario: AttackScenario):
        """Simulate a specific type of attack"""
        
        if attack_type == AttackType.PORT_SCAN:
            self._simulate_port_scan(scenario)
        elif attack_type == AttackType.DOS_ATTACK:
            self._simulate_dos_attack(scenario)
        elif attack_type == AttackType.DATA_EXFILTRATION:
            self._simulate_data_exfiltration(scenario)
        elif attack_type == AttackType.DNS_TUNNELING:
            self._simulate_dns_tunneling(scenario)
        elif attack_type == AttackType.LATERAL_MOVEMENT:
            self._simulate_lateral_movement(scenario)
        elif attack_type == AttackType.SUSPICIOUS_PROTOCOL:
            self._simulate_suspicious_protocol(scenario)
        elif attack_type == AttackType.NORMAL_TRAFFIC:
            self._simulate_normal_traffic(scenario.duration)

    def _simulate_port_scan(self, scenario: AttackScenario):
        """Simulate port scanning attack"""
        attacker_ip = "192.168.1.200"  # Suspicious external IP
        target_ips = ["192.168.1.100", "192.168.1.101", "192.168.1.102"]
        
        # Common ports to scan
        ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1433, 3389, 5432, 5900]
        
        start_time = time.time()
        while self.is_running and (time.time() - start_time) < scenario.duration:
            # Rapid port scanning
            for port in random.sample(ports, min(15, len(ports))):  # Scan 15 ports rapidly
                target_ip = random.choice(target_ips)
                
                event = LiveNetworkEvent(
                    timestamp=datetime.now(),
                    source_ip=attacker_ip,
                    dest_ip=target_ip,
                    protocol="TCP",
                    size=64,
                    port=port,
                    raw_packet=None
                )
                
                self._send_event(event)
                time.sleep(0.1)  # Very fast scanning
            
            time.sleep(1)  # Brief pause between scan bursts

    def _simulate_dos_attack(self, scenario: AttackScenario):
        """Simulate DoS attack"""
        attacker_ip = "10.0.0.100"  # Attacker IP
        target_ip = "192.168.1.1"   # Target server
        
        start_time = time.time()
        while self.is_running and (time.time() - start_time) < scenario.duration:
            # High volume of packets
            for _ in range(int(50 * scenario.intensity)):  # 50+ packets per burst
                event = LiveNetworkEvent(
                    timestamp=datetime.now(),
                    source_ip=attacker_ip,
                    dest_ip=target_ip,
                    protocol="TCP",
                    size=random.randint(64, 1500),
                    port=80,
                    raw_packet=None
                )
                
                self._send_event(event)
                time.sleep(0.01)  # Very fast packet rate
            
            time.sleep(0.5)  # Brief pause between bursts

    def _simulate_data_exfiltration(self, scenario: AttackScenario):
        """Simulate data exfiltration"""
        internal_ip = "192.168.1.150"  # Compromised internal machine
        external_ip = "203.0.113.50"   # External C&C server
        
        start_time = time.time()
        while self.is_running and (time.time() - start_time) < scenario.duration:
            # Large data transfers
            for _ in range(int(20 * scenario.intensity)):
                event = LiveNetworkEvent(
                    timestamp=datetime.now(),
                    source_ip=internal_ip,
                    dest_ip=external_ip,
                    protocol="TCP",
                    size=random.randint(10000, 50000),  # Large packets
                    port=443,
                    raw_packet=None
                )
                
                self._send_event(event)
                time.sleep(0.2)
            
            time.sleep(2)  # Pause between transfer bursts

    def _simulate_dns_tunneling(self, scenario: AttackScenario):
        """Simulate DNS tunneling"""
        internal_ip = "192.168.1.175"  # Compromised machine
        dns_server = "8.8.8.8"         # DNS server
        
        start_time = time.time()
        while self.is_running and (time.time() - start_time) < scenario.duration:
            # Excessive DNS queries
            for _ in range(int(30 * scenario.intensity)):
                event = LiveNetworkEvent(
                    timestamp=datetime.now(),
                    source_ip=internal_ip,
                    dest_ip=dns_server,
                    protocol="DNS",
                    size=random.randint(100, 500),
                    port=53,
                    raw_packet=None
                )
                
                self._send_event(event)
                time.sleep(0.1)  # Very frequent DNS queries
            
            time.sleep(1)

    def _simulate_lateral_movement(self, scenario: AttackScenario):
        """Simulate lateral movement (internal network scanning)"""
        attacker_ip = "192.168.1.180"  # Compromised internal machine
        
        # Internal IP range to scan
        internal_ips = [f"192.168.1.{i}" for i in range(100, 200)]
        
        start_time = time.time()
        while self.is_running and (time.time() - start_time) < scenario.duration:
            # Scan multiple internal IPs
            for target_ip in random.sample(internal_ips, min(25, len(internal_ips))):
                event = LiveNetworkEvent(
                    timestamp=datetime.now(),
                    source_ip=attacker_ip,
                    dest_ip=target_ip,
                    protocol="TCP",
                    size=64,
                    port=random.choice([22, 135, 139, 445, 3389]),  # Common internal ports
                    raw_packet=None
                )
                
                self._send_event(event)
                time.sleep(0.2)
            
            time.sleep(2)

    def _simulate_suspicious_protocol(self, scenario: AttackScenario):
        """Simulate suspicious protocol usage"""
        suspicious_ip = "192.168.1.190"
        target_ip = "192.168.1.1"
        
        # Unusual protocols
        suspicious_protocols = ["RAW", "UNKNOWN", "ICMP"]
        
        start_time = time.time()
        while self.is_running and (time.time() - start_time) < scenario.duration:
            event = LiveNetworkEvent(
                timestamp=datetime.now(),
                source_ip=suspicious_ip,
                dest_ip=target_ip,
                protocol=random.choice(suspicious_protocols),
                size=random.randint(64, 1000),
                port=random.choice([1, 7, 9, 11, 13, 15, 17, 19]),
                raw_packet=None
            )
            
            self._send_event(event)
            time.sleep(0.5)

    def _simulate_normal_traffic(self, duration: int):
        """Simulate normal network traffic"""
        protocols = ['HTTP', 'HTTPS', 'DNS', 'SSH', 'FTP', 'SMTP']
        source_ips = ['192.168.1.100', '192.168.1.101', '10.0.0.5', '172.16.0.10']
        dest_ips = ['8.8.8.8', '1.1.1.1', '192.168.1.1', '172.16.0.1']
        
        start_time = time.time()
        while self.is_running and (time.time() - start_time) < duration:
            event = LiveNetworkEvent(
                timestamp=datetime.now(),
                source_ip=random.choice(source_ips),
                dest_ip=random.choice(dest_ips),
                protocol=random.choice(protocols),
                size=random.randint(64, 1500),
                port=random.choice([80, 443, 53, 22, 21, 25]),
                raw_packet=None
            )
            
            self._send_event(event)
            time.sleep(random.uniform(0.5, 3.0))  # Normal traffic intervals

    def _send_event(self, event: LiveNetworkEvent):
        """Send event to callback function"""
        if self.callback_func:
            try:
                self.callback_func(event)
            except Exception as e:
                self.logger.error(f"Error in event callback: {e}")

    def stop_simulation(self):
        """Stop the simulation"""
        self.is_running = False
        if self.attack_thread:
            self.attack_thread.join(timeout=5)

    def get_available_scenarios(self) -> Dict[str, AttackScenario]:
        """Get list of available attack scenarios"""
        return {scenario.attack_type.value: scenario for scenario in self.scenarios.values()}

def main():
    """Test the threat simulator"""
    import sys
    import os
    
    # Add src to path
    sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
    
    def test_callback(event):
        print(f"Event: {event.source_ip} -> {event.dest_ip} ({event.protocol}:{event.port}) {event.size} bytes")
    
    simulator = ThreatSimulator(callback_func=test_callback)
    
    print("🎯 Threat Simulator Test")
    print("Available scenarios:")
    for name, scenario in simulator.get_available_scenarios().items():
        print(f"  - {name}: {scenario.description}")
    
    print("\nStarting 60-second attack simulation...")
    simulator.simulate_attack_sequence(duration=60)

if __name__ == "__main__":
    main()
