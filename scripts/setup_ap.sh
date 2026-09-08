#!/bin/bash

# Source config
. ../config.txt

version_check () {
	echo "System info"
	echo "==========="
	git rev-parse --short HEAD 2>/dev/null || echo "(source tarball, no git revision)"
	uname -a
	openssl version
	dnsmasq --version
	hostapd -v
	/usr/bin/env python3 --version
	echo "==========="
}

setup () {
	rfkill unblock wifi

	wpa_supplicant_pid=$(pidof wpa_supplicant)
	if [ -n "$wpa_supplicant_pid" ]; then
		echo "Attempting to stop wpa_supplicant"
		sudo kill $wpa_supplicant_pid
	fi

	# Rather than stopping NetworkManager outright -- which also tears down any
	# wired connection, often the machine's only route to the internet -- hand
	# just the wireless interface over to hostapd. Fall back to stopping the
	# service where nmcli is unavailable or refuses.
	if test -d /etc/NetworkManager; then
		if command -v nmcli >/dev/null && sudo nmcli device set "$WLAN" managed no 2>/dev/null; then
			echo "Released $WLAN from NetworkManager (other connections stay up)"
			sleep 1
		else
			echo "Stopping NetworkManager..."
			if ! sudo systemctl stop network-manager 2>/dev/null
			then
				if ! sudo systemctl stop NetworkManager 2>/dev/null
				then
					echo "** Failed to stop NetworkManager, AP may not work! **"
				fi
			fi
		fi
	fi

	echo "Configuring AP interface..."
	sudo ip link set $WLAN down
	sudo ip addr add $GATEWAY/24 dev $WLAN
	sudo ip link set $WLAN up
	sudo ip route add 10.42.42.0/24 dev $WLAN src $GATEWAY
	sudo ip route add 255.255.255.255 dev $WLAN

	echo "Starting DNSMASQ server..."
	sudo dnsmasq \
		--no-resolv \
		--interface=$WLAN \
		--bind-interfaces \
		--listen-address=$GATEWAY \
		--except-interface=lo \
		--dhcp-range=10.42.42.10,10.42.42.40,12h \
		--address=/#/$GATEWAY

	echo "Starting AP on $WLAN..."

	# Read hostapd.conf with interface from stdin for
	# backward compatibility (hostapd < v2.6). See #398
	printf "$(cat hostapd.conf)\ninterface=$WLAN" | sudo hostapd /dev/stdin
}

cleanup () {
	sudo pkill hostapd
	echo "AP closed"

	echo "Stopping DNSMASQ server..."
	sudo pkill dnsmasq

	# Give the wireless interface back and clear the static AP address, so
	# normal WiFi works again after flashing.
	if test -d /etc/NetworkManager; then
		sudo ip addr flush dev "$WLAN" 2>/dev/null
		if command -v nmcli >/dev/null && sudo nmcli device set "$WLAN" managed yes 2>/dev/null; then
			echo "Returned $WLAN to NetworkManager"
		else
			echo "Restarting NetworkManager..."
			if ! sudo systemctl restart network-manager 2>/dev/null
			then
				if ! sudo systemctl restart NetworkManager 2>/dev/null
				then
					echo "** Failed to restart NetworkManager: network may not be functional! **"
				fi
			fi
		fi
	fi
}

version_check
trap cleanup EXIT
setup
