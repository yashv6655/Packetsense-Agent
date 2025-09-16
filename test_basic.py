#!/usr/bin/env python3

import sys
import os

def test_imports():
    """Test that all required modules can be imported"""
    try:
        import streamlit
        print("Streamlit imported successfully")
    except ImportError as e:
        print(f"Streamlit import failed: {e}")
        return False

    try:
        import pyshark
        print("PyShark imported successfully")
    except ImportError as e:
        print(f"PyShark import failed: {e}")
        print("Install Wireshark first: brew install wireshark (macOS) or apt-get install tshark (Linux)")
        return False

    try:
        import openai
        print("OpenAI imported successfully")
    except ImportError as e:
        print(f"OpenAI import failed: {e}")
        return False

    try:
        import pandas
        print("Pandas imported successfully")
    except ImportError as e:
        print(f"Pandas import failed: {e}")
        return False

    try:
        import plotly
        print("Plotly imported successfully")
    except ImportError as e:
        print(f"Plotly import failed: {e}")
        return False

    return True

def test_modules():
    """Test that our custom modules can be imported"""
    try:
        from src.packet_analyzer import PacketAnalyzer
        print("PacketAnalyzer imported successfully")

        analyzer = PacketAnalyzer()
        print("PacketAnalyzer instantiated successfully")
    except Exception as e:
        print(f"PacketAnalyzer failed: {e}")
        return False

    try:
        from src.ai_agent import PacketAnalysisAgent
        print("PacketAnalysisAgent imported successfully")

        # Don't instantiate AI agent without API key
        print("PacketAnalysisAgent ready (API key check skipped)")
    except Exception as e:
        print(f"PacketAnalysisAgent failed: {e}")
        return False

    return True

def check_env():
    """Check environment setup"""
    if os.path.exists('.env'):
        print(".env file found")
    else:
        print(".env file not found - create one from .env.example")

    api_key = os.getenv('OPENAI_API_KEY')
    if api_key:
        print("OPENAI_API_KEY is set")
    else:
        print("OPENAI_API_KEY not found in environment")

def main():
    print("PacketSense AI - System Check\n")

    print("Testing package imports...")
    imports_ok = test_imports()

    print("\nTesting custom modules...")
    modules_ok = test_modules()

    print("\nChecking environment...")
    check_env()

    print("\n" + "="*50)
    if imports_ok and modules_ok:
        print("All tests passed! Run 'streamlit run app.py' to start PacketSense")
    else:
        print("Some tests failed. Check the errors above and install missing dependencies.")
        sys.exit(1)

if __name__ == "__main__":
    main()