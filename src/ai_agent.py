import openai
from typing import Dict, Any, List
import os
from dotenv import load_dotenv

load_dotenv()

class PacketAnalysisAgent:
    def __init__(self):
        self.client = openai.OpenAI(api_key=os.getenv('OPENAI_API_KEY'))

    def analyze_traffic(self, packet_data: Dict[str, Any], suspicious_patterns: List[str]) -> str:
        system_prompt = """You are PacketSense, an AI network security analyst.
        Your job is to explain network traffic analysis in simple, clear language that both
        beginners and experts can understand.

        Focus on:
        1. What's happening in the network traffic
        2. Whether anything looks suspicious or normal
        3. Educational explanations of protocols and patterns
        4. Security implications in plain English

        Be conversational but professional. Use emojis sparingly for clarity."""

        user_prompt = f"""
        Analyze this network traffic data and explain what's happening:

        TRAFFIC SUMMARY:
        - Total packets: {packet_data.get('total_packets', 0)}
        - Total data: {packet_data.get('total_size', 0)} bytes
        - Protocols seen: {packet_data.get('protocols', {})}
        - Top source IPs: {packet_data.get('top_src_ips', {})}
        - Top destination IPs: {packet_data.get('top_dst_ips', {})}

        SUSPICIOUS PATTERNS DETECTED:
        {chr(10).join(suspicious_patterns) if suspicious_patterns else "None detected"}

        Please provide:
        1. A simple explanation of what this network activity represents
        2. Assessment of whether this looks normal or concerning
        3. Educational insights about the protocols and patterns seen
        4. Any security recommendations
        """

        try:
            response = self.client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                max_tokens=800,
                temperature=0.7
            )

            return response.choices[0].message.content

        except Exception as e:
            return f"Sorry, I couldn't analyze this traffic right now. Error: {str(e)}"

    def explain_protocol(self, protocol: str) -> str:
        protocol_explanations = {
            "HTTP": "HTTP (HyperText Transfer Protocol) - Regular web browsing traffic. Unencrypted.",
            "HTTPS": "HTTPS (HTTP Secure) - Encrypted web browsing traffic. Secure.",
            "TCP": "TCP (Transmission Control Protocol) - Reliable data transmission protocol.",
            "UDP": "UDP (User Datagram Protocol) - Fast, unreliable data transmission.",
            "DNS": "DNS (Domain Name System) - Translates website names to IP addresses.",
            "ARP": "ARP (Address Resolution Protocol) - Maps IP addresses to MAC addresses.",
            "ICMP": "ICMP (Internet Control Message Protocol) - Network diagnostic messages (like ping).",
            "SSH": "SSH (Secure Shell) - Encrypted remote access protocol.",
            "FTP": "FTP (File Transfer Protocol) - File transfer, often unencrypted.",
            "SMTP": "SMTP (Simple Mail Transfer Protocol) - Email sending protocol."
        }

        return protocol_explanations.get(protocol, f"{protocol} - Network protocol (details not available)")

    def generate_security_tips(self, analysis_data: Dict[str, Any]) -> List[str]:
        tips = []

        protocols = analysis_data.get('protocols', {})

        if 'HTTP' in protocols and protocols['HTTP'] > 10:
            tips.append("🔒 Consider using HTTPS instead of HTTP for better security")

        if 'DNS' in protocols and protocols['DNS'] > 100:
            tips.append("🌐 High DNS activity detected - monitor for DNS tunneling attacks")

        if len(analysis_data.get('top_dst_ips', {})) > 20:
            tips.append("🎯 Many different destinations - could indicate scanning activity")

        if not tips:
            tips.append("✅ Traffic patterns appear normal from a security perspective")

        return tips