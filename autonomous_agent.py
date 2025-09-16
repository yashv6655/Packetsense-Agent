import time
from apscheduler.schedulers.background import BackgroundScheduler
from src.live_capture import LiveCapture
from src.packet_analyzer import PacketAnalyzer
from src.ai_agent import PacketAnalysisAgent
from src.agent_memory import AgentMemory

def analyze_and_report(analyzer: PacketAnalyzer, ai_agent: PacketAnalysisAgent, memory: AgentMemory):
    """Analyzes the captured packets and generates a report."""
    print("Analyzing captured packets...")
    analysis_data = analyzer.analyze_basic_stats()
    suspicious_patterns = analyzer.detect_suspicious_patterns()

    if not analysis_data or analysis_data.get('total_packets', 0) == 0:
        print("No packets to analyze.")
        return

    # Log the analysis
    memory.log_analysis(analysis_data)

    # Get AI analysis
    ai_analysis = ai_agent.analyze_traffic(analysis_data, suspicious_patterns)
    print("\n--- AI Analysis ---")
    print(ai_analysis)
    print("--- End of Analysis ---\n")

    # If suspicious patterns are found, log them as threats
    if suspicious_patterns:
        print("Suspicious patterns detected!")
        for pattern in suspicious_patterns:
            memory.log_threat(pattern)
            print(f"- {pattern}")

def main():
    # Configuration
    capture_interface = "en0"  # Replace with your network interface (e.g., eth0, wlan0)
    analysis_interval = 30  # seconds

    # Initialization
    live_capture = LiveCapture(interface=capture_interface)
    analyzer = PacketAnalyzer()
    ai_agent = PacketAnalysisAgent()
    memory = AgentMemory(db_path="src/agent_memory.db")

    print(f"Starting autonomous agent on interface '{capture_interface}'")
    print(f"Analyzing traffic every {analysis_interval} seconds.")

    # Start the analysis scheduler
    scheduler = BackgroundScheduler()
    scheduler.add_job(
        analyze_and_report,
        'interval',
        seconds=analysis_interval,
        args=[analyzer, ai_agent, memory]
    )
    scheduler.start()

    try:
        # Start capturing packets
        packet_iterator = live_capture.capture_packets()
        for packet in packet_iterator:
            analyzer.add_packet(packet)

    except KeyboardInterrupt:
        print("\nShutting down the agent...")
        scheduler.shutdown()
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        if scheduler.running:
            scheduler.shutdown()

if __name__ == "__main__":
    main()
