# PacketSense AI - Autonomous Network Security Agent

A fully autonomous AI agent that monitors network traffic in real-time, detects threats, and takes automated security actions. This is a learning project to understand how AI-powered network security automation works.

## What It Does

This agent uses AI with a **ReAct (Reason + Act) loop** to monitor and secure your network. It can:

- **Monitor Network Traffic** - Capture and analyze live network packets
- **Detect Threats** - Identify suspicious patterns and security risks
- **Take Automated Actions** - Block IPs, send alerts, investigate incidents
- **Learn and Adapt** - Improve threat detection over time
- **Provide Safety Controls** - Prevent destructive actions with whitelists and rate limits

## Architecture

The project consists of several key components:

1. **AI Agent Core** (`src/ai_agent.py`, `src/autonomous_agent.py`) - Implements the ReAct loop for autonomous decision making
2. **Network Monitoring** (`src/live_capture.py`, `src/packet_analyzer.py`) - Captures and analyzes network traffic
3. **Threat Detection** (`src/threat_detector.py`) - AI-powered threat identification
4. **Safety Controls** (`src/safety_controls.py`) - Prevents harmful actions
5. **Dashboard Interface** (`agent_dashboard.py`) - Web UI for monitoring and control

### How the ReAct Loop Works

```
Network Traffic
    ↓
[AI Agent analyzes packets and detects patterns]
    ↓
Does the agent detect a threat?
    ├─ YES → Analyze threat level → Take appropriate action → Log results
    └─ NO  → Continue monitoring → Update learning model
```

The agent iteratively monitors, analyzes, and responds to network events in real-time.

## Setup

### Prerequisites

- Python 3.8+
- Network monitoring tools (Wireshark/tshark)
- OpenAI API key (optional, for enhanced AI features)

### Installation

1. Clone or download this repository

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Install network monitoring tools:
   - **macOS**: `brew install wireshark`
   - **Linux**: `sudo apt-get install tshark`
   - **Windows**: Install Wireshark

4. Create a `.env` file with your API key (optional):
```bash
echo "OPENAI_API_KEY=your_api_key_here" > .env
```

## Usage

### Dashboard Mode (Recommended)

Run the web dashboard:
```bash
streamlit run agent_dashboard.py
```

Open your browser to `http://localhost:8502` and:
1. Configure settings in the sidebar
2. Select your network interface
3. Choose **Simulation Mode** for safe testing
4. Set monitoring duration
5. Click **"Start Agent"**
6. Watch real-time metrics and activity!

### Command Line Mode

```bash
# Simulation mode (safe for testing)
cd src
python complete_agent.py --simulation --duration 60

# Live monitoring (requires caution)
cd src
python complete_agent.py --interface en0 --duration 3600
```

### Quick Start Script

```bash
./run.sh
```

## Safety Features

For safety, the agent includes multiple protection mechanisms:

- **Simulation Mode**: No real network actions taken during testing
- **IP Whitelisting**: Prevents blocking critical infrastructure IPs
- **Rate Limiting**: Limits automated actions per hour
- **Auto-rollback**: Automatically unblocks IPs after timeout
- **Human Override**: Manual control when needed
- **Action Logging**: Complete audit trail of all actions taken

## Project Structure

```
.
├── .env                 # API keys (not in git)
├── .gitignore          # Git ignore rules
├── README.md           # This file
├── requirements.txt    # Python dependencies
├── agent_dashboard.py  # Web dashboard interface
├── run.sh             # Quick start script
├── src/               # Core agent components
│   ├── ai_agent.py           # Main AI agent logic
│   ├── autonomous_agent.py   # Autonomous operation
│   ├── live_capture.py      # Network packet capture
│   ├── packet_analyzer.py   # Packet analysis
│   ├── threat_detector.py   # Threat detection
│   └── safety_controls.py   # Safety mechanisms
└── investigations/    # Stored investigation results
```

## How It Compares to Production Tools

This is a **learning project** focused on understanding AI-powered network security. Production tools have:

- Enterprise-grade threat intelligence
- Advanced machine learning models
- Integration with SIEM systems
- Sophisticated policy management
- Multi-tenant support
- Compliance reporting
- Much more...

This project demonstrates the **core concepts** of autonomous network security in a simplified, educational format.

## Technical Details

- **AI Model**: OpenAI GPT-4 for threat analysis and decision making
- **Network Capture**: Wireshark/tshark for packet capture
- **Safety Controls**: Multi-layer protection against harmful actions
- **Real-time Processing**: Live network traffic analysis
- **Learning System**: Continuous improvement from network patterns

## Extending the Agent

Want to add new capabilities? The modular architecture makes it easy:

1. **New Threat Types**: Add detection logic to `threat_detector.py`
2. **Custom Actions**: Extend `action_executor.py` with new response types
3. **Enhanced Analysis**: Improve packet analysis in `packet_analyzer.py`
4. **Safety Rules**: Add new protection mechanisms to `safety_controls.py`

The agent will automatically use your new capabilities!

## Troubleshooting

**Permission errors**: Make sure you have appropriate network monitoring permissions

**No packets captured**: Check that you're monitoring the correct network interface

**API key errors**: Ensure `.env` exists and contains `OPENAI_API_KEY=...` (optional)

**Dashboard won't start**: Verify Streamlit is installed and port 8502 is available

## Important Safety Notes

- **Start with Simulation Mode** for testing
- **Live Mode** can take real network actions
- Only monitor networks you own or have permission to access
- The agent learns and adapts over time - monitor its behavior
- Always have manual override capabilities available

## Learn More

- [OpenAI API Documentation](https://platform.openai.com/docs)
- [Wireshark Documentation](https://www.wireshark.org/docs/)
- [Network Security Monitoring Best Practices](https://www.sans.org/white-papers/network-security-monitoring/)
- [ReAct Pattern for AI Agents](https://arxiv.org/abs/2210.03629)

## License

This is a learning project. Use it to understand AI-powered network security