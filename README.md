# PacketSense AI - Autonomous Network Security Agent

A fully autonomous AI agent that monitors network traffic in real-time, detects threats, and takes automated security actions.

## Quick Launch Commands

### 1. Agent Dashboard (Recommended)
```bash
cd packetsense
source venv/bin/activate
streamlit run agent_dashboard.py
```
**Open browser to:** `http://localhost:8502`

### 2. Command Line Interface
```bash
cd packetsense
source venv/bin/activate
cd src
python complete_agent.py --simulation --duration 60
```

**Note:** The `complete_agent.py` file is located in the `src/` subdirectory.

### 3. Quick Start Script
```bash
cd packetsense
source venv/bin/activate
./run.sh
```

## What the AI Agent Does

- **Real-time Network Monitoring**: Captures and analyzes live network traffic
- **Autonomous Threat Detection**: Uses AI to identify security threats
- **Automated Response**: Takes real actions (block IPs, send alerts, investigate)
- **Continuous Learning**: Improves threat detection over time
- **Safety Controls**: Prevents destructive actions with whitelists and rate limits

## Setup Requirements

### Install Dependencies
```bash
cd packetsense
pip install -r requirements.txt
```

### System Requirements
- **macOS**: `brew install wireshark`
- **Linux**: `sudo apt-get install tshark`
- **Windows**: Install Wireshark

### API Key Setup (Optional)
```bash
echo "OPENAI_API_KEY=your_api_key_here" > packetsense/.env
```

## Usage

### Dashboard Mode (Recommended)
1. Run: `streamlit run agent_dashboard.py`
2. Open browser to `http://localhost:8502`
3. Configure settings in sidebar:
   - Select network interface
   - Choose **Simulation Mode** for testing
   - Set duration (60 seconds recommended)
4. Click **"Start Agent"**
5. Watch real-time metrics and activity!

### Command Line Mode
```bash
# Simulation mode (safe for testing)
cd packetsense/src
python complete_agent.py --simulation --duration 60

# Live monitoring (requires caution)
cd packetsense/src
python complete_agent.py --interface en0 --duration 3600
```

## Safety Features

- **Simulation Mode**: No real network actions taken
- **IP Whitelisting**: Prevents blocking critical IPs
- **Rate Limiting**: Limits actions per hour
- **Auto-rollback**: Automatically unblocks IPs after timeout
- **Human Override**: Manual control when needed

## Important Notes

- **Start with Simulation Mode** for testing
- **Live Mode** can take real network actions
- Only monitor networks you own or have permission to access
- The agent learns and adapts over time