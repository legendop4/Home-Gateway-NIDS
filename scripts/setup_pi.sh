#!/usr/bin/env bash
# ==============================================================================
# Home-Gateway NIDS: Raspberry Pi Provisioning & Setup Script
# Configures Pi as WiFi Access Point + NAT Router + Inline Suricata + NIDS Gateway
# ==============================================================================

set -e

if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run as root: sudo bash scripts/setup_pi.sh"
  exit 1
fi

echo "[*] Step 1: Updating packages and installing dependencies..."
apt-get update
apt-get install -y hostapd dnsmasq iptables-persistent suricata python3-pip python3-venv

echo "[*] Step 2: Unmasking and configuring hostapd..."
systemctl unmask hostapd || true

if [ -z "$WIFI_PASSPHRASE" ]; then
  read -s -p "Enter WiFi AP Passphrase (minimum 8 characters): " WIFI_PASSPHRASE
  echo ""
fi

if [ ${#WIFI_PASSPHRASE} -lt 8 ]; then
  echo "[-] WiFi Passphrase must be at least 8 characters."
  exit 1
fi

cat << EOF > /etc/hostapd/hostapd.conf
interface=wlan0
driver=nl80211
ssid=HomeGateway-NIDS
hw_mode=g
channel=7
wmm_enabled=0
macaddr_acl=0
auth_algs=1
wpa=2
wpa_passphrase=${WIFI_PASSPHRASE}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP
EOF

echo 'DAEMON_CONF="/etc/hostapd/hostapd.conf"' > /etc/default/hostapd

echo "[*] Step 3: Configuring static IP on wlan0..."
if [ -f /etc/dhcpcd.conf ]; then
cat << 'EOF' >> /etc/dhcpcd.conf
interface wlan0
    static ip_address=192.168.10.1/24
    nohook wpa_supplicant
EOF
fi

# Modern Debian / NetworkManager / systemd-networkd static IP fallback
if command -v nmcli >/dev/null 2>&1; then
    nmcli con add type wifi ifname wlan0 mode ap con-name HomeGateway-NIDS ssid HomeGateway-NIDS ip4 192.168.10.1/24 || true
fi
ip addr replace 192.168.10.1/24 dev wlan0 2>/dev/null || true

echo "[*] Step 4: Configuring dnsmasq DHCP..."
mv /etc/dnsmasq.conf /etc/dnsmasq.conf.orig 2>/dev/null || true
cat << 'EOF' > /etc/dnsmasq.conf
interface=wlan0
dhcp-range=192.168.10.50,192.168.10.200,255.255.255.0,24h
domain=nids.local
address=/gw.nids.local/192.168.10.1
EOF

echo "[*] Step 5: Enabling IPv4 Forwarding & NAT Masquerade..."
mkdir -p /etc/sysctl.d
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-nids.conf
if [ -f /etc/sysctl.conf ]; then
    sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf || true
fi
sysctl -w net.ipv4.ip_forward=1 || true
sysctl --system 2>/dev/null || true

iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE || true
iptables -A FORWARD -i eth0 -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT || true
iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT || true
netfilter-persistent save || true

echo "[*] Step 6: Setting up Suricata rules..."
mkdir -p /etc/suricata/rules
cp config/rules/recon.rules /etc/suricata/rules/
cp config/suricata.yaml.template /etc/suricata/suricata.yaml

echo "[*] Step 7: Creating systemd unit for NIDS Gateway..."
APP_DIR=$(pwd)
PYTHON_BIN="/usr/bin/python3"
if [ -n "$VIRTUAL_ENV" ] && [ -f "$VIRTUAL_ENV/bin/python" ]; then
    PYTHON_BIN="$VIRTUAL_ENV/bin/python"
elif [ -f "${APP_DIR}/venv311/bin/python" ]; then
    PYTHON_BIN="${APP_DIR}/venv311/bin/python"
elif [ -f "${APP_DIR}/venv/bin/python" ]; then
    PYTHON_BIN="${APP_DIR}/venv/bin/python"
elif [ -f "${APP_DIR}/.venv/bin/python" ]; then
    PYTHON_BIN="${APP_DIR}/.venv/bin/python"
fi

cat << EOF > /etc/systemd/system/nids-gateway.service
[Unit]
Description=Home-Gateway NIDS Daemon
After=network.target suricata.service

[Service]
Type=simple
User=root
WorkingDirectory=${APP_DIR}
ExecStart=${PYTHON_BIN} ${APP_DIR}/run.py --mode live
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable hostapd dnsmasq suricata nids-gateway.service || true

echo "[+] Raspberry Pi Setup Complete! Reboot the Pi to activate AP Gateway and NIDS."
