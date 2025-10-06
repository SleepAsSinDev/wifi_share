#!/usr/bin/env bash
set -euo pipefail

# -------- Defaults (override by flags) --------
WAN_IF="wlan0"
LAN_IF="eth0"
SUBNET_CIDR="192.168.50.0/24"
GATEWAY_IP="192.168.50.1"
DHCP_START="192.168.50.10"
DHCP_END="192.168.50.100"
DNS_SERVERS="1.1.1.1,8.8.8.8"

usage() {
  cat <<EOF
Usage: sudo bash $0 [--wan wlan0] [--lan eth0] [--subnet 192.168.50.0/24] [--gw 192.168.50.1] [--range 192.168.50.10-192.168.50.100] [--dns 1.1.1.1,8.8.8.8]

Examples:
  sudo bash $0
  sudo bash $0 --wan wlan0 --lan eth0 --subnet 192.168.88.0/24 --gw 192.168.88.1 --range 192.168.88.10-192.168.88.150
EOF
}

# -------- Parse args --------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --wan) WAN_IF="$2"; shift 2 ;;
    --lan) LAN_IF="$2"; shift 2 ;;
    --subnet) SUBNET_CIDR="$2"; shift 2 ;;
    --gw) GATEWAY_IP="$2"; shift 2 ;;
    --range)
      IFS='-' read -r DHCP_START DHCP_END <<< "$2"; shift 2 ;;
    --dns) DNS_SERVERS="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1"; usage; exit 1 ;;
  esac
done

# -------- Pre-flight --------
if [[ $EUID -ne 0 ]]; then
  echo "Please run as root: sudo bash $0"
  exit 1
fi

if ! ip link show "$WAN_IF" >/dev/null 2>&1; then
  echo "WARN: WAN interface $WAN_IF not found. Continue anyway..."
fi
if ! ip link show "$LAN_IF" >/dev/null 2>&1; then
  echo "ERROR: LAN interface $LAN_IF not found."
  exit 1
fi

echo "==> Settings
  WAN_IF      : $WAN_IF
  LAN_IF      : $LAN_IF
  SUBNET_CIDR : $SUBNET_CIDR
  GATEWAY_IP  : $GATEWAY_IP
  DHCP_RANGE  : $DHCP_START - $DHCP_END
  DNS         : $DNS_SERVERS
"

# -------- Detect distro --------
. /etc/os-release
DISTRO_ID="${ID:-unknown}"
echo "Detected distro: $DISTRO_ID"

# -------- Install packages --------
echo "==> Installing packages: dnsmasq iptables-persistent (or netfilter-persistent)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y dnsmasq iptables-persistent || apt-get install -y dnsmasq netfilter-persistent

# -------- Configure static IP on LAN --------
if [[ "$DISTRO_ID" == "ubuntu" ]]; then
  echo "==> Configuring netplan for $LAN_IF ($GATEWAY_IP)"
  NETPLAN_FILE="/etc/netplan/60-${LAN_IF}-nat.yaml"
  cat > "$NETPLAN_FILE" <<EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    ${LAN_IF}:
      dhcp4: no
      addresses: [${GATEWAY_IP}/24]
EOF
  netplan apply
else
  # Assume Raspberry Pi OS / Debian with dhcpcd
  echo "==> Configuring dhcpcd for $LAN_IF ($GATEWAY_IP)"
  DHCPCD_CONF="/etc/dhcpcd.conf"
  sed -i "/^interface ${LAN_IF}$/,/^$/d" "$DHCPCD_CONF" || true
  cat >> "$DHCPCD_CONF" <<EOF

# Static for ${LAN_IF} (NAT gateway)
interface ${LAN_IF}
static ip_address=${GATEWAY_IP}/24
nolink
EOF
  systemctl restart dhcpcd || true
fi

# -------- Configure dnsmasq (DHCP on LAN_IF) --------
echo "==> Configuring dnsmasq"
mkdir -p /etc/dnsmasq.d
DNSMASQ_LAN_CONF="/etc/dnsmasq.d/${LAN_IF}.conf"
cat > "$DNSMASQ_LAN_CONF" <<EOF
interface=${LAN_IF}
bind-interfaces
dhcp-range=${DHCP_START},${DHCP_END},12h
dhcp-option=3,${GATEWAY_IP}          # Default gateway
dhcp-option=6,${DNS_SERVERS}         # DNS servers
# Avoid DNS loop if Pi itself runs a resolver
no-resolv
server=1.1.1.1
server=8.8.8.8
EOF

systemctl enable dnsmasq
systemctl restart dnsmasq

# -------- Enable IP forwarding --------
echo "==> Enabling IPv4 forwarding"
SYSCTL_FILE="/etc/sysctl.d/99-ipforward.conf"
echo "net.ipv4.ip_forward=1" > "$SYSCTL_FILE"
sysctl --system >/dev/null

# -------- NAT & forward rules --------
echo "==> Setting iptables NAT/forward rules"
iptables -t nat -C POSTROUTING -o "$WAN_IF" -j MASQUERADE 2>/dev/null || \
iptables -t nat -A POSTROUTING -o "$WAN_IF" -j MASQUERADE

iptables -C FORWARD -i "$WAN_IF" -o "$LAN_IF" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -i "$WAN_IF" -o "$LAN_IF" -m state --state RELATED,ESTABLISHED -j ACCEPT

iptables -C FORWARD -i "$LAN_IF" -o "$WAN_IF" -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -i "$LAN_IF" -o "$WAN_IF" -j ACCEPT

# Persist rules
if command -v netfilter-persistent >/dev/null 2>&1; then
  netfilter-persistent save
  systemctl enable netfilter-persistent
else
  # iptables-persistent
  mkdir -p /etc/iptables
  iptables-save > /etc/iptables/rules.v4
  # v6 not required here, but create empty file
  test -f /etc/iptables/rules.v6 || touch /etc/iptables/rules.v6
fi

# -------- Final info --------
cat <<EOF

========================================================
✅ Done! Your Pi is now a Wi-Fi→LAN NAT router.

Connect your Router's WAN/Internet port to ${LAN_IF} of the Pi.

Router settings:
  • WAN/Internet type: DHCP (Automatic)
  • If you instead plug into a LAN port and want "AP mode",
    please DISABLE DHCP on your Router to avoid conflict.

Debug / Verify:
  • On Pi:     ip a | grep -E "${LAN_IF}|${WAN_IF}"
  • DHCP log:  journalctl -u dnsmasq -e
  • Clients should get IP in: ${DHCP_START}-${DHCP_END}
  • From a client: ping ${GATEWAY_IP} and open websites

Change later:
  • DHCP:   /etc/dnsmasq.d/${LAN_IF}.conf  → systemctl restart dnsmasq
  • NAT:    iptables rules (saved via netfilter/iptables-persistent)
  • Forward: ${SYSCTL_FILE} (ip_forward=1)

Uninstall / Revert (manual):
  • apt remove dnsmasq iptables-persistent -y
  • Remove: /etc/dnsmasq.d/${LAN_IF}.conf
  • Ubuntu: rm /etc/netplan/60-${LAN_IF}-nat.yaml && netplan apply
  • RPi OS: edit /etc/dhcpcd.conf (remove static block) && systemctl restart dhcpcd
  • Clear rules: iptables -F; iptables -t nat -F; netfilter-persistent save (if used)

Happy networking! 🚀
========================================================
EOF
