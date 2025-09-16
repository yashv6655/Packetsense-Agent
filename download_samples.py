#!/usr/bin/env python3
"""
Sample PCAP file downloader for PacketSense AI
Downloads safe, educational packet capture files for learning
"""

import os
import requests
from pathlib import Path

def download_file(url, filename):
    """Download a file from URL to data/ directory"""
    data_dir = Path("data")
    data_dir.mkdir(exist_ok=True)

    filepath = data_dir / filename

    if filepath.exists():
        print(f"{filename} already exists")
        return

    print(f"Downloading {filename}...")
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()

        with open(filepath, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

        print(f"Downloaded {filename} ({filepath.stat().st_size} bytes)")
    except Exception as e:
        print(f"Failed to download {filename}: {e}")

def main():
    """Download sample packet capture files"""
    print("PacketSense AI - Sample Data Downloader\n")

    # Safe sample files from Wireshark's sample captures
    samples = [
        {
            "url": "https://gitlab.com/wireshark/wireshark/-/wikis/uploads/__moin_import__/attachments/SampleCaptures/dns.cap",
            "filename": "dns_queries.pcap",
            "description": "DNS lookup examples - great for beginners"
        }
    ]

    print("Available sample files:")
    for i, sample in enumerate(samples, 1):
        print(f"{i}. {sample['filename']} - {sample['description']}")

    print("\nStarting downloads...\n")

    for sample in samples:
        download_file(sample["url"], sample["filename"])

    print(f"\nSample files downloaded to ./data/ directory")
    print("💡 Upload these files in PacketSense AI to start analyzing!")

if __name__ == "__main__":
    main()