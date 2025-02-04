#!/bin/bash
set -e

echo "[+] Atualizando pacotes do sistema e instalando dependências..."
sudo apt update && sudo apt install -y \
    git curl wget python3 python3-pip python3-venv \
    build-essential libpcap-dev \
    bind9-dnsutils libnet-whois-ip-perl libio-socket-inet6-perl

echo "[+] Verificando se Go está instalado..."
if ! command -v go &> /dev/null; then
    echo "[+] Go não encontrado. Instalando..."
    wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
    rm go1.21.5.linux-amd64.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
else
    echo "[+] Go já está instalado!"
fi

echo "[+] Criando diretório para binários do Go..."
mkdir -p ~/go/bin
export PATH=$PATH:~/go/bin
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc

echo "[+] Instalando ferramentas baseadas em Go..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/OWASP/Amass/v4/...@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/haccer/subjack@latest

echo "[+] Instalando ferramentas baseadas em Python..."
python3 -m pip install --upgrade pip
python3 -m pip install virtualenv

echo "[+] Instalando Sublist3r..."
git clone https://github.com/aboul3la/Sublist3r.git ~/Sublist3r
cd ~/Sublist3r
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
deactivate
cd ~

echo "[+] Instalando dnsrecon..."
git clone https://github.com/darkoperator/dnsrecon.git ~/dnsrecon
cd ~/dnsrecon
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
deactivate
cd ~

echo "[+] Instalando dnsenum..."
git clone https://github.com/fwaeytens/dnsenum.git ~/dnsenum
cd ~/dnsenum
# Linha 'deactivate' removida pois não há ambiente virtual
cd ~

echo "[+] Clonando e configurando o DNS157 - Advanced DNS Recon Tool..."
git clone https://github.com/rafaelcorvino1/DNS157---Advanced-DNS-Recon-Tool.git ~/DNS157
cd ~/DNS157

# Garante que o DNS157.py possua shebang
if ! head -n 1 DNS157.py | grep -q "^#!"; then
    sed -i '1i #!/usr/bin/env python3' DNS157.py
fi

chmod +x DNS157.py
sudo ln -sf "$(pwd)/DNS157.py" /usr/local/bin/DNS157

echo "[+] Instalação concluída!"

echo -e "\n[INFO] Agora você pode usar o DNS157 diretamente do terminal."
echo -e "[INFO] Reinicie seu shell ou execute:"
echo -e "    export PATH=\$PATH:/usr/local/go/bin:~/go/bin\n"
echo -e "[INFO] Exemplo de uso:\n"
echo -e "    DNS157 example.com\n"
