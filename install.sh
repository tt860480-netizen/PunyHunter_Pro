#!/bin/bash
# install.sh

echo "Installing PunyHunter Pro..."

# Create virtual environment
python3 -m venv punyhunter_env
source punyhunter_env/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create directories
mkdir -p {config,results,wordlists,logs}

# Set permissions
chmod +x punyhunter_pro.py

echo "Installation completed!"
echo "Run: python3 punyhunter_pro.py --gui"
