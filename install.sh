#!/bin/bash
set -e
set -o pipefail

echo "[+] Updating system packages and installing dependencies..."
sudo apt update && sudo apt install -y \
    git curl wget python3 python3-pip python3-venv \
    build-essential libpcap-dev \
    bind9-dnsutils libnet-whois-ip-perl libio-socket-inet6-perl dos2unix

# Check and install Go
if ! command -v go &> /dev/null; then
    echo "[+] Go not found. Installing..."
    wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
    rm go1.21.5.linux-amd64.tar.gz
fi

# Add Go to PATH if not already present
if [[ ":$PATH:" != *":/usr/local/go/bin:"* ]]; then
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    export PATH=$PATH:/usr/local/go/bin
fi

# Configure Go binary directory
mkdir -p ~/go/bin
if [[ ":$PATH:" != *":$HOME/go/bin:"* ]]; then
    echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
    export PATH=$PATH:~/go/bin
fi

# Install Go-based tools
echo "[+] Installing Go-based tools..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/owasp-amass/amass/v4/...@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

echo "[+] Installing Python-based tools..."
python3 -m pip install --upgrade pip
python3 -m pip install virtualenv

# Install Sublist3r
echo "[+] Installing Sublist3r..."
if [ ! -d "$HOME/Sublist3r" ]; then
    git clone https://github.com/aboul3la/Sublist3r.git "$HOME/Sublist3r"
    python3 -m venv "$HOME/Sublist3r/venv"
    source "$HOME/Sublist3r/venv/bin/activate"
    pip install -r "$HOME/Sublist3r/requirements.txt"
    deactivate
fi
sudo ln -sf "$HOME/Sublist3r/sublist3r.py" /usr/local/bin/sublist3r

# Install dnsrecon
echo "[+] Installing dnsrecon..."
if [ ! -d "$HOME/dnsrecon" ]; then
    git clone https://github.com/darkoperator/dnsrecon.git "$HOME/dnsrecon"
    python3 -m venv "$HOME/dnsrecon/venv"
    source "$HOME/dnsrecon/venv/bin/activate"
    pip install -r "$HOME/dnsrecon/requirements.txt"
    deactivate
fi
sudo ln -sf "$HOME/dnsrecon/dnsrecon.py" /usr/local/bin/dnsrecon

# Install dnsenum
echo "[+] Installing dnsenum..."
if [ ! -d "$HOME/dnsenum" ]; then
    git clone https://github.com/fwaeytens/dnsenum.git "$HOME/dnsenum"
fi
sudo ln -sf "$HOME/dnsenum/dnsenum.pl" /usr/local/bin/dnsenum

# Install DNS157
echo "[+] Setting up DNS157..."
cd "$(dirname "$0")"

# Fix Windows line endings
echo "[+] Fixing line formatting in DNS157.py..."
dos2unix DNS157.py

# Remove UTF-8 BOM if present
sed -i '1s/^\xEF\xBB\xBF//' DNS157.py

# Ensure DNS157.py has the correct shebang
if ! head -n 1 DNS157.py | grep -q "^#!"; then
    sed -i '1i #!/usr/bin/env python3' DNS157.py
fi

chmod +x DNS157.py

# Ensure correct permissions for /usr/local/bin/
sudo mkdir -p /usr/local/bin
sudo chmod 755 /usr/local/bin
sudo ln -sf "$(pwd)/DNS157.py" /usr/local/bin/DNS157

echo "[+] Installation completed!"

echo -e "\n[INFO] You can now use DNS157 directly from the terminal."
echo -e "[INFO] Restart your shell or run:"
echo -e "    export PATH=\$PATH:/usr/local/go/bin:~/go/bin\n"
echo -e "[INFO] Example usage:\n"
echo -e "    DNS157 example.com\n"
