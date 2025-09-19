#!/bin/bash

echo "Installation de l'outil de sécurité Python..."
echo "Mise à jour du système..."

sudo apt update
sudo apt upgrade -y

echo "Installation des dépendances système..."
sudo apt install -y python3 python3-pip python3-venv
sudo apt install -y build-essential libssl-dev libffi-dev
sudo apt install -y tcpdump traceroute nmap wireshark-common
sudo apt install -y git curl wget

echo "Création de l'environnement virtuel..."
python3 -m venv security-env
source security-env/bin/activate

echo "Installation des dépendances Python..."
pip install --upgrade pip
pip install -r requirements.txt

echo "Installation des outils supplémentaires..."
sudo apt install -y sqlmap hydra john hashcat binwalk
sudo apt install -y nikto wpscan gobuster dirb

echo "Configuration des permissions..."
sudo chmod +x main.sh
sudo chmod +x main.py
find programs/ -name "*.py" -exec sudo chmod +x {} \;

echo "Installation terminée!"
echo "Pour utiliser l'outil:"
echo "  source security-env/bin/activate"
echo "  ./main.sh --help"