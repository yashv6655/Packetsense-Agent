#!/bin/bash

# PacketSense AI Quick Start Script

echo "🔍 PacketSense AI - Quick Start"
echo "==============================="

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Check if requirements are installed
if ! python -c "import streamlit" 2>/dev/null; then
    echo "📥 Installing dependencies..."
    pip install -r requirements.txt
fi

# Check for .env file
if [ ! -f ".env" ]; then
    echo "⚙️ Creating .env file..."
    cp .env.example .env
    echo "⚠️  Please edit .env file and add your OpenAI API key!"
    echo "   You can get one at: https://platform.openai.com/api-keys"
fi

echo "🚀 Starting PacketSense AI..."
echo "   Open http://localhost:8501 in your browser"
echo ""

streamlit run app.py