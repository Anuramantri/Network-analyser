#!/bin/bash
if [ $# -ne 1 ]; then
    echo "Usage: $0 <file>"
    exit 1
fi

# Function to check if a package is installed
check_package() {
    dpkg -l | grep -q "$1"
}

# List of required packages
REQUIRED_PACKAGES=("build-essential" "g++" "net-tools" "iputils-ping" "python3" "python3-pip")

echo "Checking for required packages..."

# Install missing packages
for package in "${REQUIRED_PACKAGES[@]}"; do
    if ! check_package "$package"; then
        sudo apt update && sudo apt install -y "$package"
    else
        continue
    fi
done

# Install Python dependencies
echo "Installing required Python libraries..."
pip3 install --upgrade networkx pyvis

# Compile the traceroute C++ program
g++ -o traceroute traceroute.cpp

# Run traceroute (requires sudo)
echo "Running traceroute..."
sudo ./traceroute "$1"

# Run the network visualization script
echo "Running network.py..."
python3 network.py

echo "done"