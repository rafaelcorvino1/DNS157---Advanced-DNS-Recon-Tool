#!/bin/bash
set -e
set -o pipefail

echo "[+] Atualizando pacotes do sistema e instalando dependências..."
sudo apt update && sudo apt install -y \
    git curl wget python3 python3-pip python3-venv \
    build-essential libpcap-dev \
    bind9-dnsutils libnet-whois-ip-perl libio-socket-inet6-perl

# Verifica e instala Go
if ! command -v go &> /dev/null; then
    echo "[+] Go não encontrado. Instalando..."
    wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
    rm go1.21.5.linux-amd64.tar.gz
fi

# Adiciona Go ao PATH se ainda não estiver presente
if [[ ":$PATH:" != *":/usr/local/go/bin:"* ]]; then
    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
fi

# Configura diretório de binários do Go
mkdir -p ~/go/bin
if [[ ":$PATH:" != *":$HOME/go/bin:"* ]]; then
    export PATH=$PATH:~/go/bin
    echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
fi

# Instala ferramentas baseadas em Go
echo "[+] Instalando ferramentas baseadas em Go..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/owasp-amass/amass/v4/...@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

echo "[+] Instalando ferramentas baseadas em Python..."
python3 -m pip install --upgrade pip
python3 -m pip install virtualenv

# Instala Sublist3r
echo "[+] Instalando Sublist3r..."
if [ ! -d "$HOME/Sublist3r" ]; then
    git clone https://github.com/aboul3la/Sublist3r.git "$HOME/Sublist3r"
    python3 -m venv "$HOME/Sublist3r/venv"
    source "$HOME/Sublist3r/venv/bin/activate"
    pip install -r "$HOME/Sublist3r/requirements.txt"
    deactivate
else
    echo "[+] Sublist3r já instalado."
fi

# Instala dnsrecon
echo "[+] Instalando dnsrecon..."
if [ ! -d "$HOME/dnsrecon" ]; then
    git clone https://github.com/darkoperator/dnsrecon.git "$HOME/dnsrecon"
    python3 -m venv "$HOME/dnsrecon/venv"
    source "$HOME/dnsrecon/venv/bin/activate"
    pip install -r "$HOME/dnsrecon/requirements.txt"
    deactivate
else
    echo "[+] dnsrecon já instalado."
fi

# Instala dnsenum
echo "[+] Instalando dnsenum..."
if [ ! -d "$HOME/dnsenum" ]; then
    git clone https://github.com/fwaeytens/dnsenum.git "$HOME/dnsenum"
else
    echo "[+] dnsenum já instalado."
fi

# Instalação do DNS157
echo "[+] Clonando e configurando o DNS157 - Advanced DNS Recon Tool..."
if [ ! -d "$HOME/DNS157" ]; then
    git clone https://github.com/rafaelcorvino1/DNS157---Advanced-DNS-Recon-Tool.git "$HOME/DNS157"
else
    echo "[+] DNS157 já instalado. Atualizando..."
    cd "$HOME/DNS157" && git pull && cd ~
fi

cd "$HOME/DNS157"

# Garante que DNS157.py tenha o shebang correto
if ! head -n 1 DNS157.py | grep -q "^#!"; then
    sed -i '1i #!/usr/bin/env python3' DNS157.py
fi

chmod +x DNS157.py
sudo ln -sf "$HOME/DNS157/DNS157.py" /usr/local/bin/DNS157

echo "[+] Instalação concluída!"

echo -e "\n[INFO] Agora você pode usar o DNS157 diretamente do terminal."
echo -e "[INFO] Reinicie seu shell ou execute:"
echo -e "    export PATH=\$PATH:/usr/local/go/bin:~/go/bin\n"
echo -e "[INFO] Exemplo de uso:\n"
echo -e "    DNS157 example.com\n"
