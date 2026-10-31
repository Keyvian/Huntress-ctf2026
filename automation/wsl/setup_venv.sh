#!/bin/sh
# Rebuild the CTF python venv from scratch (self-heal after a Kali python upgrade
# orphans the old site-packages). Idempotent. Usage: ~/ctf/setup_venv.sh
set -e
cd "$HOME/ctf"
python3 -m venv --clear --without-pip "$HOME/ctf-venv"
curl -sSL https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py
"$HOME/ctf-venv/bin/python" /tmp/get-pip.py >/dev/null 2>&1
"$HOME/ctf-venv/bin/python" -m pip install -q -r "$HOME/ctf/requirements.txt"
"$HOME/ctf-venv/bin/python" -c "import lief,pefile,dnfile,PIL,capstone,pyzipper,requests,pyzbar.pyzbar,pytesseract; from elftools.elf.elffile import ELFFile; print('venv rebuilt OK:', lief.__version__)"
