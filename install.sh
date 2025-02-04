#!/bin/bash
set -e

REQUIRED_GO_VERSION="1.21.5"
GO_TARBALL="go${REQUIRED_GO_VERSION}.linux-amd64.tar.gz"
GO_DOWNLOAD_URL="https://go.dev/dl/${GO_TARBALL}"

echo "[+] Updating packages and installing system dependencies..."
sudo apt update && sudo apt install -y git curl wget python3 python3-pip python3-venv build-essential libpcap-dev bind9-dnsutils

if ! grep -q 'export PATH=\$PATH:/usr/local/go/bin' ~/.bashrc; then
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
fi
if ! grep -q 'export PATH=\$PATH:~/go/bin' ~/.bashrc; then
    echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
fi
export PATH=$PATH:/usr/local/go/bin:~/go/bin

echo "[+] Checking for Go installation..."
if command -v go &> /dev/null; then
    INSTALLED_GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    if [ "$INSTALLED_GO_VERSION" != "$REQUIRED_GO_VERSION" ]; then
        echo "[+] Installed Go version ($INSTALLED_GO_VERSION) does not match required version ($REQUIRED_GO_VERSION). Updating..."
        wget "$GO_DOWNLOAD_URL"
        sudo rm -rf /usr/local/go
        sudo tar -C /usr/local -xzf "$GO_TARBALL"
        rm "$GO_TARBALL"
    else
        echo "[+] Go is already installed and up-to-date ($INSTALLED_GO_VERSION)!"
    fi
else
    echo "[+] Go not found. Installing..."
    wget "$GO_DOWNLOAD_URL"
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "$GO_TARBALL"
    rm "$GO_TARBALL"
fi

echo "[+] Creating directory for Go binaries..."
mkdir -p ~/go/bin

echo "[+] Installing Go-based tools..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/owasp-amass/amass/v4/...@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/haccer/subjack@latest

echo "[+] Upgrading pip and installing virtualenv..."
python3 -m pip install --upgrade pip
python3 -m pip install virtualenv

if [ ! -d ~/Sublist3r ]; then
    echo "[+] Cloning Sublist3r..."
    git clone https://github.com/aboul3la/Sublist3r.git ~/Sublist3r
else
    echo "[+] Sublist3r already exists, updating..."
    cd ~/Sublist3r && git pull && cd ~
fi
cd ~/Sublist3r
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
deactivate
cd ~

if [ ! -d ~/dnsrecon ]; then
    echo "[+] Cloning dnsrecon..."
    git clone https://github.com/darkoperator/dnsrecon.git ~/dnsrecon
else
    echo "[+] dnsrecon already exists, updating..."
    cd ~/dnsrecon && git pull && cd ~
fi
cd ~/dnsrecon
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
deactivate
cd ~

if [ ! -d ~/dnsenum ]; then
    echo "[+] Cloning dnsenum..."
    git clone https://github.com/fwaeytens/dnsenum.git ~/dnsenum
else
    echo "[+] dnsenum already exists, updating..."
    cd ~/dnsenum && git pull && cd ~
fi
cd ~/dnsenum
sudo apt install -y libnet-whois-ip-perl libio-socket-inet6-perl
cd ~

echo "[+] Finished! To apply PATH changes, restart your terminal or run 'source ~/.bashrc'."


echo "[+] Installation completed!"

echo -e "\n[INFO]Now you can now use DNS157 directly from the terminal(run 'source ~/.bashrc') ."
echo -e "[INFO] Example usage:\n"
echo -e "DNS157 example.com\n"

