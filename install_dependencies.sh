#!/bin/bash

# ReconSuite Dependency Installer
# For Kali Linux and other Debian-based distributions

echo "Installing ReconSuite dependencies..."

# Update package lists
sudo apt update

# Install Python3 and pip if not already installed
sudo apt install -y python3 python3-pip python3-venv

# Install required system dependencies
sudo apt install -y nmap whois

# Create virtual environment (optional but recommended)
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

echo "Dependencies installed successfully!"
echo "To activate the virtual environment, run: source venv/bin/activate"
echo "To run the application, navigate to the project directory and run: python main.py"