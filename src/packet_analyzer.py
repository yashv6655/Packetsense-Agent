import pyshark
import pandas as pd
from typing import Dict, List, Any
from collections import defaultdict

class PacketAnalyzer:
    def __init__(self):
        self.packets = []
        self.analysis_data = {}

    def add_packet(self, packet: pyshark.packet.packet.Packet):
        """Adds a packet to the internal list for analysis."""
        self.packets.append(packet)

    def analyze_basic_stats(self) -> Dict[str, Any]:
        if not self.packets:
            return {}

        protocol_counts = defaultdict(int)
        src_ips = defaultdict(int)
        dst_ips = defaultdict(int)
        packet_count = 0
        total_size = 0

        try:
            for packet in self.packets:
                packet_count += 1

                # Get packet length
                try:
                    if hasattr(packet, 'frame_info') and hasattr(packet.frame_info, 'len'):
                        total_size += int(packet.frame_info.len)
                except (ValueError, AttributeError):
                    pass

                # Get highest layer protocol
                try:
                    if hasattr(packet, 'highest_layer'):
                        highest_layer = packet.highest_layer
                        protocol_counts[highest_layer] += 1
                except AttributeError:
                    protocol_counts['UNKNOWN'] += 1

                # Extract IP addresses if available
                try:
                    if hasattr(packet, 'ip'):
                        src_ips[packet.ip.src] += 1
                        dst_ips[packet.ip.dst] += 1
                except AttributeError:
                    pass

            # Clear the packet list after analysis
            self.packets = []

        except Exception as e:
            print(f"Error analyzing packets: {e}")

        self.analysis_data = {
            'total_packets': packet_count,
            'total_size': total_size,
            'protocols': dict(protocol_counts),
            'top_src_ips': dict(sorted(src_ips.items(), key=lambda x: x[1], reverse=True)[:10]),
            'top_dst_ips': dict(sorted(dst_ips.items(), key=lambda x: x[1], reverse=True)[:10])
        }

        return self.analysis_data

    def get_summary_text(self) -> str:
        if not self.analysis_data or self.analysis_data.get('total_packets', 0) == 0:
            return "No analysis data available"

        data = self.analysis_data
        summary = f"""
Network Traffic Analysis Summary:

📊 Basic Statistics:
- Total Packets: {data['total_packets']}
- Total Data: {data['total_size']:,} bytes ({data['total_size']/1024/1024:.2f} MB)

🔗 Protocol Breakdown:
"""

        for protocol, count in data['protocols'].items():
            percentage = (count / data['total_packets']) * 100
            summary += f"- {protocol}: {count} packets ({percentage:.1f}%)\n"

        summary += f"\n🌐 Top Source IPs:\n"
        for ip, count in list(data['top_src_ips'].items())[:5]:
            summary += f"- {ip}: {count} packets\n"

        summary += f"\n🎯 Top Destination IPs:\n"
        for ip, count in list(data['top_dst_ips'].items())[:5]:
            summary += f"- {ip}: {count} packets\n"

        return summary

    def detect_suspicious_patterns(self) -> List[str]:
        suspicious = []

        if not self.analysis_data:
            return suspicious

        data = self.analysis_data

        # Check for potential port scanning
        if len(data['top_dst_ips']) > 50:
            suspicious.append("🚨 Potential port scanning detected - many different destination IPs")

        # Check for unusual protocol distribution
        if 'TCP' in data['protocols'] and data['protocols']['TCP'] > data['total_packets'] * 0.8:
            suspicious.append("⚠️ High TCP traffic ratio - potential data transfer or attack")

        # Check for single IP dominance
        if data['top_src_ips']:
            top_src_count = list(data['top_src_ips'].values())[0]
            if top_src_count > data['total_packets'] * 0.7:
                top_src_ip = list(data['top_src_ips'].keys())[0]
                suspicious.append(f"🔍 Single source IP dominance: {top_src_ip} ({top_src_count} packets)")

        return suspicious