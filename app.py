import streamlit as st
import os
import tempfile
import plotly.express as px
import pandas as pd
from src.packet_analyzer import PacketAnalyzer
from src.ai_agent import PacketAnalysisAgent

st.set_page_config(
    page_title="PacketSense AI",
    page_icon="",
    layout="wide"
)

def main():
    st.title("PacketSense AI - Network Security Agent")
    st.markdown("### Upload a packet capture file and let AI explain what's happening")

    # Sidebar for configuration
    st.sidebar.header("Configuration")

    # Check if OpenAI API key is configured
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        st.sidebar.error("OpenAI API key not found. Please create a .env file with your OPENAI_API_KEY.")
        st.stop()
    else:
        st.sidebar.success("OpenAI API key configured")

    # File upload
    uploaded_file = st.file_uploader(
        "Choose a packet capture file",
        type=['pcap', 'pcapng'],
        help="Upload a .pcap or .pcapng file to analyze network traffic"
    )

    if uploaded_file is not None:
        # Save uploaded file temporarily
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp_file:
            tmp_file.write(uploaded_file.getvalue())
            tmp_file_path = tmp_file.name

        st.success(f"File uploaded: {uploaded_file.name}")

        # Initialize analyzers
        analyzer = PacketAnalyzer()
        ai_agent = PacketAnalysisAgent()

        # Analysis progress
        progress_bar = st.progress(0)
        status_text = st.empty()

        try:
            # Load and analyze the pcap file
            status_text.text("Loading packet capture file...")
            progress_bar.progress(25)

            if not analyzer.load_pcap(tmp_file_path):
                st.error("Failed to load packet capture file")
                return

            status_text.text("Analyzing network traffic...")
            progress_bar.progress(50)

            # Perform basic analysis
            analysis_data = analyzer.analyze_basic_stats()
            suspicious_patterns = analyzer.detect_suspicious_patterns()

            progress_bar.progress(75)
            status_text.text("Generating AI analysis...")

            # Get AI analysis
            ai_analysis = ai_agent.analyze_traffic(analysis_data, suspicious_patterns)
            security_tips = ai_agent.generate_security_tips(analysis_data)

            progress_bar.progress(100)
            status_text.text("Analysis complete!")

            # Display results
            col1, col2 = st.columns(2)

            with col1:
                st.header("Traffic Statistics")

                # Basic stats
                st.metric("Total Packets", f"{analysis_data['total_packets']:,}")
                st.metric("Total Data", f"{analysis_data['total_size']:,} bytes")

                # Protocol breakdown chart
                if analysis_data['protocols']:
                    protocols_df = pd.DataFrame(
                        list(analysis_data['protocols'].items()),
                        columns=['Protocol', 'Count']
                    )
                    fig = px.pie(protocols_df, values='Count', names='Protocol',
                                title="Protocol Distribution")
                    st.plotly_chart(fig, use_container_width=True)

                # Top IPs
                st.subheader("🌐 Top Source IPs")
                for ip, count in list(analysis_data['top_src_ips'].items())[:5]:
                    st.write(f"• **{ip}**: {count} packets")

            with col2:
                st.header("AI Analysis")
                st.write(ai_analysis)

                st.subheader("Suspicious Patterns")
                if suspicious_patterns:
                    for pattern in suspicious_patterns:
                        st.warning(pattern)
                else:
                    st.success("No suspicious patterns detected")

                st.subheader("Security Tips")
                for tip in security_tips:
                    st.info(tip)

            # Protocol explanations
            st.header("Protocol Explanations")
            for protocol in analysis_data['protocols'].keys():
                with st.expander(f"What is {protocol}?"):
                    st.write(ai_agent.explain_protocol(protocol))

            # Raw data for advanced users
            with st.expander("🔧 Raw Analysis Data"):
                st.json(analysis_data)

        except Exception as e:
            st.error(f"Error during analysis: {str(e)}")
            st.info("This might be due to an unsupported file format or corrupted data.")

        finally:
            # Clean up temporary file
            if os.path.exists(tmp_file_path):
                os.unlink(tmp_file_path)

    else:
        # Show example and instructions
        st.info("Upload a packet capture file to get started!")

        st.markdown("""
        ### How to get packet capture files:

        1. **Wireshark**: Install Wireshark and capture your own network traffic
        2. **Sample files**: Download sample captures from:
           - [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures)
           - [Malware Traffic Analysis](https://malware-traffic-analysis.net/training-exercises.html)
        3. **tcpdump**: Use command line tools to capture traffic

        ### What PacketSense analyzes:
        - Basic traffic statistics and protocol breakdown
        - Suspicious activity detection
        - AI-powered plain English explanations
        - Security recommendations and tips
        """)

if __name__ == "__main__":
    main()