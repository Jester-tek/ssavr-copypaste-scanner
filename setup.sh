#!/bin/bash
# Tor Clipboard Scanner - Automated Installer

echo "================================================"
echo "🚀 Installing Tor Clipboard Scanner Dependencies"
echo "================================================"

echo ""
echo "[1/3] Updating system packages and installing Tor..."
sudo apt update
sudo apt install -y tor python3-pip python3-venv

echo ""
echo "[2/3] Setting up isolated Python environment..."
python3 -m venv venv
source venv/bin/activate

echo ""
echo "[3/3] Installing required Python libraries..."
pip install -r requirements.txt

echo ""
echo "================================================"
echo "✅ Installation Complete!"
echo "================================================"
echo ""
echo "To start the scanner, run these two commands:"
echo "  source venv/bin/activate"
echo "  python3 main.py"
echo ""
echo "Happy scanning! 🌐"
