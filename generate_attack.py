#!/usr/bin/env python3
"""
Simple attack generator for testing specific threat scenarios
"""

import time
import random
import sys
import os
from datetime import datetime

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

try:
    from src.live_capture import LiveNetworkEvent
    from src.threat_simulator import ThreatSimulator, AttackType
except ImportError:
    from live_capture import LiveNetworkEvent
    from threat_simulator import ThreatSimulator, AttackType

def generate_port_scan(duration=30):
    """Generate a port scan attack"""
    print(f"🎯 Generating port scan attack for {duration} seconds...")
    
    def callback(event):
        print(f"SCAN: {event.source_ip} -> {event.dest_ip}:{event.port} ({event.protocol})")
    
    simulator = ThreatSimulator(callback_func=callback)
    simulator.simulate_attack_sequence(duration=duration, attack_types=[AttackType.PORT_SCAN])

def generate_dos_attack(duration=20):
    """Generate a DoS attack"""
    print(f"🎯 Generating DoS attack for {duration} seconds...")
    
    def callback(event):
        print(f"DoS: {event.source_ip} -> {event.dest_ip} ({event.size} bytes)")
    
    simulator = ThreatSimulator(callback_func=callback)
    simulator.simulate_attack_sequence(duration=duration, attack_types=[AttackType.DOS_ATTACK])

def generate_data_exfiltration(duration=40):
    """Generate data exfiltration"""
    print(f"🎯 Generating data exfiltration for {duration} seconds...")
    
    def callback(event):
        print(f"EXFIL: {event.source_ip} -> {event.dest_ip} ({event.size} bytes)")
    
    simulator = ThreatSimulator(callback_func=callback)
    simulator.simulate_attack_sequence(duration=duration, attack_types=[AttackType.DATA_EXFILTRATION])

def generate_dns_tunneling(duration=35):
    """Generate DNS tunneling"""
    print(f"🎯 Generating DNS tunneling for {duration} seconds...")
    
    def callback(event):
        print(f"DNS: {event.source_ip} -> {event.dest_ip} ({event.protocol})")
    
    simulator = ThreatSimulator(callback_func=callback)
    simulator.simulate_attack_sequence(duration=duration, attack_types=[AttackType.DNS_TUNNELING])

def generate_lateral_movement(duration=40):
    """Generate lateral movement"""
    print(f"🎯 Generating lateral movement for {duration} seconds...")
    
    def callback(event):
        print(f"LATERAL: {event.source_ip} -> {event.dest_ip}:{event.port}")
    
    simulator = ThreatSimulator(callback_func=callback)
    simulator.simulate_attack_sequence(duration=duration, attack_types=[AttackType.LATERAL_MOVEMENT])

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate specific attack patterns')
    parser.add_argument('attack', choices=['port_scan', 'dos', 'exfil', 'dns', 'lateral'],
                       help='Type of attack to generate')
    parser.add_argument('--duration', type=int, default=30,
                       help='Duration in seconds (default: 30)')
    
    args = parser.parse_args()
    
    print("🎯 PacketSense Attack Generator")
    print("=" * 40)
    print(f"Attack type: {args.attack}")
    print(f"Duration: {args.duration} seconds")
    print()
    
    if args.attack == 'port_scan':
        generate_port_scan(args.duration)
    elif args.attack == 'dos':
        generate_dos_attack(args.duration)
    elif args.attack == 'exfil':
        generate_data_exfiltration(args.duration)
    elif args.attack == 'dns':
        generate_dns_tunneling(args.duration)
    elif args.attack == 'lateral':
        generate_lateral_movement(args.duration)
    
    print("\n✅ Attack generation completed!")

if __name__ == "__main__":
    main()
