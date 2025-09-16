#!/usr/bin/env python3
"""
Debug script to test pyshark functionality
"""

import pyshark
import os

def debug_pcap():
    """Debug PCAP file parsing"""
    print("Debugging PCAP Analysis\n")

    sample_file = "data/dns_queries.pcap"
    if not os.path.exists(sample_file):
        print("Sample file not found")
        return

    print(f"File: {sample_file}")
    print(f"File size: {os.path.getsize(sample_file)} bytes")

    try:
        # Test basic file opening
        capture = pyshark.FileCapture(sample_file)
        print("FileCapture created successfully")

        # Try to read packets
        packet_count = 0
        for packet in capture:
            packet_count += 1
            print(f"  Packet {packet_count}:")
            print(f"    Layers: {packet.layers}")
            if hasattr(packet, 'highest_layer'):
                print(f"    Highest layer: {packet.highest_layer}")

            # Try to get frame info
            if hasattr(packet, 'frame_info'):
                if hasattr(packet.frame_info, 'len'):
                    print(f"    Length: {packet.frame_info.len}")

            # Try to get IP info
            if hasattr(packet, 'ip'):
                print(f"    Source IP: {packet.ip.src}")
                print(f"    Dest IP: {packet.ip.dst}")

            if packet_count >= 3:  # Just show first 3 packets
                break

        capture.close()
        print(f"\nSuccessfully read {packet_count} packets")

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    debug_pcap()