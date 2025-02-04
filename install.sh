
#!/bin/bash

set -e

echo "[+] Updating system packages and installing dependencies..."
sudo apt update && sudo apt install -y \
    git curl wget python3 python3-pip python3-venv \
    build-essential libpcap-dev \
    bind9-dnsutils libnet-whois-ip-perl libio-socket-inet6-perl

echo "[+] Checking if Go is installed..."
if ! command -v go &> /dev/null; then
    echo "[+] Go not found. Installing..."
    wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
    rm go1.21.5.linux-amd64.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    source ~/.bashrc
else
    echo "[+] Go is already installed!"
fi

echo "[+] Creating directory for Go binaries..."
mkdir -p ~/go/bin
export PATH=$PATH:~/go/bin
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
source ~/.bashrc

echo "[+] Installing Go-based tools..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/OWASP/Amass/v4/...@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/haccer/subjack@latest

echo "[+] Installing Python-based tools..."
python3 -m pip install --upgrade pip
python3 -m pip install virtualenv

echo "[+] Installing Sublist3r..."
git clone https://github.com/aboul3la/Sublist3r.git ~/Sublist3r
cd ~/Sublist3r
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
deactivate
cd ~

echo "[+] Installing dnsrecon..."
git clone https://github.com/darkoperator/dnsrecon.git ~/dnsrecon
cd ~/dnsrecon
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
deactivate
cd ~

echo "[+] Installing dnsenum..."
git clone https://github.com/fwaeytens/dnsenum.git ~/dnsenum
cd ~/dnsenum
deactivate
cd ~

echo "[+] Cloning and setting up DNS157 - Advanced DNS Recon Tool..."
git clone https://github.com/rafaelcorvino1/DNS157---Advanced-DNS-Recon-Tool.git ~/DNS157
cd ~/DNS157
chmod +x DNS157
sudo ln -sf $(pwd)/DNS157 /usr/local/bin/DNS157

echo "[+] Installation completed!"

echo -e "\n[INFO]Now you can now use DNS157 directly from the terminal."
echo -e "[INFO] Example usage:\n"
echo -e "DNS157 example.com\n"

