#!/usr/bin/env python3
"""
Demo script for PacketSense AI
Tests the packet analyzer with sample data
"""

import os
from src.packet_analyzer import PacketAnalyzer
from src.ai_agent import PacketAnalysisAgent

def demo_analysis():
    """Demo the packet analysis functionality"""
    print("PacketSense AI - Demo Analysis\n")

    # Check for sample file
    sample_file = "data/dns_queries.pcap"
    if not os.path.exists(sample_file):
        print("Sample file not found. Run: python download_samples.py")
        return

    print(f"Analyzing: {sample_file}")

    # Initialize analyzer
    analyzer = PacketAnalyzer()
    print("PacketAnalyzer initialized")

    # Load the sample file
    if not analyzer.load_pcap(sample_file):
        print("Failed to load pcap file")
        return

    print("PCAP file loaded successfully")

    # Perform analysis
    print("Analyzing packets...")
    analysis_data = analyzer.analyze_basic_stats()
    suspicious_patterns = analyzer.detect_suspicious_patterns()

    # Display results
    print("\n" + "="*50)
    print("ANALYSIS RESULTS")
    print("="*50)

    summary = analyzer.get_summary_text()
    print(summary)

    if suspicious_patterns:
        print("\nSUSPICIOUS PATTERNS:")
        for pattern in suspicious_patterns:
            print(f"  {pattern}")
    else:
        print("\nNo suspicious patterns detected")

    # Test AI analysis (only if API key is available)
    api_key = os.getenv('OPENAI_API_KEY')
    if api_key and api_key != 'your_openai_api_key_here':
        print("\nGetting AI Analysis...")
        try:
            ai_agent = PacketAnalysisAgent()
            ai_analysis = ai_agent.analyze_traffic(analysis_data, suspicious_patterns)
            print("\n" + "="*50)
            print("AI ANALYSIS")
            print("="*50)
            print(ai_analysis)

            security_tips = ai_agent.generate_security_tips(analysis_data)
            print("\nSECURITY TIPS:")
            for tip in security_tips:
                print(f"  {tip}")

        except Exception as e:
            print(f"AI analysis failed: {e}")
    else:
        print("\nOpenAI API key not configured - skipping AI analysis")
        print("   Add your API key to .env file to enable AI features")

    print("\nDemo complete!")
    print("Run 'streamlit run app.py' to use the web interface")

if __name__ == "__main__":
    demo_analysis()