#!/usr/bin/env python3
"""
Autonomous Agent Dashboard - Real-time monitoring interface
"""

import streamlit as st
import time
import threading
import json
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from src.complete_agent import AutonomousNetworkAgent
import os

st.set_page_config(
    page_title="PacketSense Autonomous Agent",
    page_icon="🤖",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state
if 'agent' not in st.session_state:
    st.session_state.agent = None
if 'agent_running' not in st.session_state:
    st.session_state.agent_running = False
if 'metrics_history' not in st.session_state:
    st.session_state.metrics_history = []

def create_agent():
    """Create and configure the autonomous agent"""
    config = {
        'monitoring_interval': 3,  # 3 second cycles for demo
        'openai_api_key': os.getenv('OPENAI_API_KEY'),
        'interface': st.session_state.get('selected_interface', None)
    }
    return AutonomousNetworkAgent(config)

def start_agent_background(agent, duration, simulation):
    """Start agent in background thread"""
    if agent:
        try:
            agent.start_autonomous_operation(
                duration=duration,
                simulation=simulation
            )
        except Exception as e:
            print(f"Agent error: {e}")  # Use print instead of st.error in thread
        finally:
            # Note: Can't update session state from background thread
            # The main thread will handle this
            pass

def main():
    st.title("🤖 PacketSense Autonomous AI Agent Dashboard")
    st.markdown("### Real-time Network Security Agent Monitoring")

    # Sidebar controls
    st.sidebar.header("🎛️ Agent Controls")

    # Configuration section
    st.sidebar.subheader("Configuration")

    # Interface selection
    available_interfaces = ["auto-detect", "en0", "eth0", "wlan0", "lo0"]
    selected_interface = st.sidebar.selectbox(
        "Network Interface",
        available_interfaces,
        help="Select network interface to monitor (auto-detect recommended)"
    )
    st.session_state.selected_interface = selected_interface if selected_interface != "auto-detect" else None

    # Operation mode
    simulation_mode = st.sidebar.checkbox(
        "🧪 Simulation Mode",
        value=True,
        help="Run in simulation mode (generates fake traffic for demo)"
    )

    # Duration setting
    duration = st.sidebar.number_input(
        "Duration (seconds)",
        min_value=10,
        max_value=300,
        value=60,
        help="How long to run the agent (0 = indefinite)"
    )

    # API Key status
    api_key = os.getenv('OPENAI_API_KEY')
    if api_key and api_key != 'your_openai_api_key_here':
        st.sidebar.success("✅ OpenAI API Key configured")
    else:
        st.sidebar.warning("⚠️ OpenAI API Key not configured")
        st.sidebar.info("AI threat analysis will be disabled")

    # Agent control buttons
    col1, col2 = st.sidebar.columns(2)

    with col1:
        if st.button("🚀 Start Agent", disabled=st.session_state.agent_running):
            if not st.session_state.agent:
                st.session_state.agent = create_agent()

            st.session_state.agent_running = True

            # Start agent in background thread
            agent_thread = threading.Thread(
                target=start_agent_background,
                args=(st.session_state.agent, duration, simulation_mode),
                daemon=True
            )
            agent_thread.start()

            st.success("🤖 Agent started!")
            st.rerun()

    with col2:
        if st.button("🛑 Stop Agent", disabled=not st.session_state.agent_running):
            if st.session_state.agent:
                st.session_state.agent.stop_autonomous_operation()
                st.session_state.agent_running = False
                st.success("Agent stopped!")
                st.rerun()

    # Main dashboard area
    if st.session_state.agent and st.session_state.agent_running:
        # Check if agent is still running
        if not st.session_state.agent.is_running:
            st.session_state.agent_running = False
            st.rerun()
        
        # Get live status
        try:
            status = st.session_state.agent.get_live_status()

            # Add current status to history for graphs
            status['timestamp'] = datetime.now()
            st.session_state.metrics_history.append(status)

            # Keep only last 50 data points
            if len(st.session_state.metrics_history) > 50:
                st.session_state.metrics_history = st.session_state.metrics_history[-50:]

            # Agent Status Overview
            st.header("📊 Agent Status")

            col1, col2, col3, col4 = st.columns(4)

            with col1:
                st.metric(
                    "🤖 Agent Status",
                    "RUNNING" if status['agent_running'] else "STOPPED",
                    delta="Active" if status['agent_running'] else None
                )

            with col2:
                uptime = status.get('uptime', 'Unknown')
                st.metric("⏱️ Uptime", uptime)

            with col3:
                events_processed = status['session_stats']['total_events_processed']
                st.metric(
                    "📡 Events Processed",
                    f"{events_processed:,}",
                    delta=f"+{len(st.session_state.metrics_history)}" if len(st.session_state.metrics_history) > 1 else None
                )

            with col4:
                actions_taken = status['security_agent']['metrics']['actions_taken']
                st.metric(
                    "🎯 Actions Taken",
                    actions_taken,
                    delta="+1" if len(st.session_state.metrics_history) > 1 and actions_taken > 0 else None
                )

            # Network Capture Stats
            st.header("📡 Network Capture")

            capture_stats = status['network_capture']
            col1, col2 = st.columns(2)

            with col1:
                st.subheader("📊 Capture Statistics")
                st.metric("Packets Captured", f"{capture_stats.get('packets_captured', 0):,}")
                st.metric("Events Processed", f"{capture_stats.get('events_processed', 0):,}")
                st.metric("Queue Size", capture_stats.get('queue_size', 0))

                if capture_stats.get('last_packet_time'):
                    last_packet = datetime.fromisoformat(capture_stats['last_packet_time'].replace('Z', '+00:00'))
                    time_since = datetime.now() - last_packet.replace(tzinfo=None)
                    st.metric("Last Packet", f"{time_since.seconds}s ago")

            with col2:
                st.subheader("🌐 Top Protocols")
                protocols = capture_stats.get('top_protocols', {})
                if protocols:
                    protocol_df = pd.DataFrame(
                        list(protocols.items()),
                        columns=['Protocol', 'Count']
                    )
                    fig = px.pie(protocol_df, values='Count', names='Protocol', title="Protocol Distribution")
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("No protocol data available yet")

            # Security Agent Status
            st.header("🛡️ Security Analysis")

            security_status = status['security_agent']
            threat_detector = status['threat_detector']

            col1, col2, col3 = st.columns(3)

            with col1:
                st.subheader("🎯 Agent Goals")
                goals = security_status.get('goals', {})
                for goal, target in goals.items():
                    st.metric(goal.replace('_', ' ').title(), f"{target:.2%}")

            with col2:
                st.subheader("🚨 Threat Detection")
                st.metric("Baseline Established", "Yes" if threat_detector['baseline_established'] else "No")
                st.metric("Baseline Events", f"{threat_detector['baseline_events']:,}")
                st.metric("AI Analysis", "Enabled" if threat_detector['ai_available'] else "Disabled")

            with col3:
                st.subheader("📈 Performance Metrics")
                metrics = security_status['metrics']
                st.metric("Threats Detected", metrics['threats_detected'])
                st.metric("False Positives", metrics['false_positives'])
                st.metric("Response Time", f"{metrics['avg_response_time']:.1f}s")

            # Live Activity Log
            st.header("📝 Live Activity Log")

            if len(st.session_state.metrics_history) > 1:
                # Create activity timeline
                timeline_data = []
                for i, record in enumerate(st.session_state.metrics_history[-10:]):  # Last 10 records
                    timeline_data.append({
                        'Time': record['timestamp'].strftime('%H:%M:%S'),
                        'Events': record['session_stats']['total_events_processed'],
                        'Actions': record['security_agent']['metrics']['actions_taken'],
                        'Packets': record['network_capture'].get('packets_captured', 0)
                    })

                if timeline_data:
                    df = pd.DataFrame(timeline_data)
                    fig = go.Figure()

                    fig.add_trace(go.Scatter(
                        x=df['Time'],
                        y=df['Events'],
                        mode='lines+markers',
                        name='Events Processed',
                        line=dict(color='blue')
                    ))

                    fig.add_trace(go.Scatter(
                        x=df['Time'],
                        y=df['Packets'],
                        mode='lines+markers',
                        name='Packets Captured',
                        line=dict(color='green'),
                        yaxis='y2'
                    ))

                    fig.update_layout(
                        title="Real-time Activity",
                        xaxis_title="Time",
                        yaxis=dict(title="Events", side='left'),
                        yaxis2=dict(title="Packets", side='right', overlaying='y'),
                        height=400
                    )

                    st.plotly_chart(fig, use_container_width=True)

            # Recent Network Events
            if st.session_state.agent and hasattr(st.session_state.agent, 'network_capture'):
                recent_events = st.session_state.agent.network_capture.get_recent_events(10)
                if recent_events:
                    st.subheader("🔍 Recent Network Events")

                    events_data = []
                    for event in recent_events[-5:]:  # Show last 5 events
                        events_data.append({
                            'Time': event.timestamp.strftime('%H:%M:%S'),
                            'Source IP': event.source_ip,
                            'Destination IP': event.dest_ip,
                            'Protocol': event.protocol,
                            'Size': f"{event.size} bytes",
                            'Port': event.port or 'N/A'
                        })

                    if events_data:
                        df = pd.DataFrame(events_data)
                        st.dataframe(df, use_container_width=True)

            # Auto-refresh every 2 seconds
            time.sleep(2)
            st.rerun()

        except Exception as e:
            st.error(f"Error getting agent status: {e}")
            st.session_state.agent_running = False

    elif st.session_state.agent and not st.session_state.agent_running:
        st.info("🤖 Agent created but not running. Click 'Start Agent' to begin autonomous operation.")

        # Show final session report if available
        if hasattr(st.session_state.agent, 'session_stats'):
            st.subheader("📊 Last Session Summary")
            stats = st.session_state.agent.session_stats

            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Events Processed", stats['total_events_processed'])
            with col2:
                st.metric("Actions Taken", stats['actions_taken'])
            with col3:
                st.metric("Threats Detected", stats['threats_detected'])
            with col4:
                st.metric("False Positives", stats['false_positives'])

    else:
        # Welcome screen
        st.header("🤖 Welcome to PacketSense Autonomous AI Agent")

        st.markdown("""
        This is a **true autonomous AI agent** that:

        ### 🎯 Core Agent Capabilities:
        - **🧠 Autonomous Decision Making** - Makes security decisions without human intervention
        - **🔄 Continuous Operation** - Runs 24/7 monitoring network traffic
        - **📊 Real-time Analysis** - Processes live network events as they happen
        - **🎯 Goal-Oriented Behavior** - Works toward security objectives
        - **🧮 Learning & Adaptation** - Improves threat detection over time
        - **⚡ Reactive Responses** - Automatically responds to detected threats

        ### 🛡️ Security Features:
        - **Live Network Capture** - Monitors real network traffic
        - **AI Threat Detection** - Uses machine learning for threat analysis
        - **Autonomous Response** - Automatically blocks threats, sends alerts
        - **Memory System** - Learns from past incidents
        - **Multiple Detection Methods** - Rule-based + Statistical + AI analysis

        ### 🚀 Getting Started:
        1. Configure network interface and duration in the sidebar
        2. Choose simulation mode for demo (or live mode for real monitoring)
        3. Click "Start Agent" to begin autonomous operation
        4. Watch the agent work in real-time!

        **⚠️ Safety Note:** In simulation mode, no real network actions are taken.
        """)

        # Quick stats about the agent
        st.subheader("🔧 Agent Specifications")
        col1, col2 = st.columns(2)

        with col1:
            st.markdown("""
            **Detection Capabilities:**
            - Port scanning detection
            - DoS attack identification
            - Data exfiltration monitoring
            - DNS tunneling detection
            - Lateral movement analysis
            """)

        with col2:
            st.markdown("""
            **Autonomous Actions:**
            - IP address blocking
            - Security alert generation
            - Threat investigation
            - Human escalation
            - Continuous monitoring
            """)

if __name__ == "__main__":
    main()