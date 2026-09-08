#!/usr/bin/env bash
set -euo pipefail

debianInstall() {
	sudo apt-get update
	# Python dependencies come from the distribution rather than pip: recent
	# releases mark the system environment as externally managed (PEP 668), so
	# a plain "pip install" fails there. sslpsk is no longer needed at all --
	# psk-frontend.py talks to OpenSSL directly -- which also removes the need
	# for a compiler and headers to build it.
	sudo apt-get install -y git iw dnsmasq rfkill hostapd screen curl mosquitto mosquitto-clients haveged net-tools iproute2 iputils-ping \
		python3-tornado python3-paho-mqtt python3-pycryptodome
}

archInstall() {
	sudo pacman -S --needed git iw dnsmasq hostapd screen curl python-pycryptodomex python-paho-mqtt python-tornado mosquitto haveged net-tools openssl
}

if [[ -e /etc/os-release ]]; then
	source /etc/os-release
else
	echo "/etc/os-release not found! Assuming debian-based system, but this will likely fail!"
	ID=debian
fi

if [[ ${ID} == 'debian' ]] || [[ ${ID_LIKE-} == 'debian' ]]; then
	debianInstall
elif [[ ${ID} == 'arch' ]] || [[ ${ID_LIKE-} == 'arch' ]]; then
	archInstall
else
	if [[ -n ${ID_LIKE-} ]]; then
		printID="${ID}/${ID_LIKE}"
	else
		printID="${ID}"
	fi
	echo "/etc/os-release found but distribution ${printID} is not explicitly supported. Assuming debian-based system, but this will likely fail!"
	debianInstall
fi

echo "Ready to start upgrade"
