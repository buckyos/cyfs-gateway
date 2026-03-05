#! /bin/bash

set -e

usage() {
    echo "Usage: $0 --port <port> [--iface <interface>] [--action add|remove]"
    echo "       $0 [--remove] --port <port> [--iface <interface>]"
    echo "       $0 <port> [interface]"
    echo ""
    echo "Examples:"
    echo "  $0 --port 1080 --iface eth0"
    echo "  $0 --port 1080 --iface eth0 --action remove"
    echo "  $0 --remove --port 1080"
    echo "  $0 1080"
}

ensure_iptables_rule() {
    local table="$1"
    local chain="$2"
    shift 2

    if iptables -t "$table" -C "$chain" "$@" 2>/dev/null; then
        echo "iptables rule already exists in $table/$chain, skipping."
    else
        iptables -t "$table" -A "$chain" "$@"
    fi
}

delete_iptables_rule() {
    local table="$1"
    local chain="$2"
    shift 2

    local removed=0
    while iptables -t "$table" -C "$chain" "$@" 2>/dev/null; do
        iptables -t "$table" -D "$chain" "$@"
        removed=1
    done

    if [ "$removed" -eq 1 ]; then
        echo "iptables rule removed from $table/$chain"
    else
        echo "iptables rule not found in $table/$chain, skipping."
    fi
}

is_private_ipv4() {
    case "$1" in
        10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

detect_lan_interface() {
    while read -r iface ip; do
        if is_private_ipv4 "$ip"; then
            echo "$iface"
            return 0
        fi
    done < <(ip -o -4 addr show scope global | awk '{print $2" "$4}' | cut -d'/' -f1)

    local default_iface
    default_iface=$(ip route show default | awk '/default/ {print $5; exit}')
    if [ -n "$default_iface" ]; then
        echo "$default_iface"
        return 0
    fi

    return 1
}

PORT=""
LAN_IFACE=""
ACTION="add"

while [ $# -gt 0 ]; do
    case "$1" in
        -p|--port)
            PORT="$2"
            shift 2
            ;;
        -i|--iface)
            LAN_IFACE="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -a|--action)
            ACTION="$2"
            shift 2
            ;;
        --remove)
            ACTION="remove"
            shift
            ;;
        *)
            if [ -z "$PORT" ]; then
                PORT="$1"
            elif [ -z "$LAN_IFACE" ]; then
                LAN_IFACE="$1"
            else
                echo "error: unknown argument $1"
                usage
                exit 1
            fi
            shift
            ;;
    esac
done

if [ -z "$PORT" ] || ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
    echo "error: invalid port: $PORT"
    usage
    exit 1
fi

if [ "$ACTION" != "add" ] && [ "$ACTION" != "remove" ]; then
    echo "error: invalid action: $ACTION"
    usage
    exit 1
fi

if [ -z "$LAN_IFACE" ]; then
    LAN_IFACE=$(detect_lan_interface || true)
    if [ -z "$LAN_IFACE" ]; then
        echo "error: failed to detect LAN interface automatically, please specify --iface"
        exit 1
    fi
fi

if ! ip link show "$LAN_IFACE" &>/dev/null; then
    echo "error: interface does not exist: $LAN_IFACE"
    exit 1
fi

echo "Using interface: $LAN_IFACE"
echo "Action: $ACTION"
echo "Target port: $PORT"

IPSET_NAME="localnetwork"

if [ "$ACTION" = "remove" ]; then
    delete_iptables_rule nat PREROUTING -i "$LAN_IFACE" -p tcp -m set ! --match-set "$IPSET_NAME" dst -j REDIRECT --to-ports "$PORT"
    delete_iptables_rule mangle PREROUTING -i "$LAN_IFACE" -p udp -m set ! --match-set "$IPSET_NAME" dst -j TPROXY --on-port "$PORT" --on-ip 127.0.0.1 --tproxy-mark 5321

    if ip rule del fwmark 5321 table 112 2>/dev/null; then
        while ip rule del fwmark 5321 table 112 2>/dev/null; do :; done
        echo "ip rule removed: fwmark 5321 table 112"
    else
        echo "ip rule not found: fwmark 5321 table 112"
    fi

    if ip route show table 112 | grep -q '^local 0.0.0.0/0 dev lo'; then
        ip route del local 0.0.0.0/0 dev lo table 112 2>/dev/null || true
        echo "ip route removed from table 112"
    else
        echo "ip route not found in table 112"
    fi

    exit 0
fi

if command -v ipset &> /dev/null; then
    echo -e "ipset already exists, skipping the installation step."
else
    echo "ipset is not installed, starting automatic installation..."

    if [ -f /etc/redhat-release ] || [ -f /etc/centos-release ]; then
        echo "The system is detected as CentOS/RHEL series, installing via yum..."
        yum install -y ipset

    elif [ -f /etc/debian_version ] || grep -qi "ubuntu" /etc/os-release; then
        echo "The system is detected as Debian/Ubuntu series, installing via apt..."
        apt-get update
        apt-get -y install ipset

    else
        echo -e "The system distribution cannot be automatically identified. Please install ipset manually."
        exit 1
    fi

    if command -v ipset &> /dev/null; then
        echo -e "ipset installed successfully!"
    else
        echo -e "The installation of ipset may fail. Please check the above output information."
        exit 1
    fi
fi

if ! ipset list "$IPSET_NAME" &>/dev/null; then
	echo "create ipset: $IPSET_NAME"
	ipset create localnetwork hash:net
	ipset add $IPSET_NAME 0.0.0.0/8
	ipset add $IPSET_NAME 127.0.0.0/8
	ipset add $IPSET_NAME 10.0.0.0/8
	ipset add $IPSET_NAME 169.254.0.0/16
	ipset add $IPSET_NAME 192.168.0.0/16
	ipset add $IPSET_NAME 224.0.0.0/4
	ipset add $IPSET_NAME 240.0.0.0/4
	ipset add $IPSET_NAME 172.16.0.0/12
	ipset add $IPSET_NAME 100.64.0.0/10
fi

IP_ADDRESSES=$(ip -o -4 addr show dev "$LAN_IFACE" scope global | awk '{print $4}' | cut -d'/' -f1)

if [ -z "$IP_ADDRESSES" ]; then
    echo "error：Failed to obtain the local IP address."
    exit 1
fi

read -ra IP_ARRAY <<< "$IP_ADDRESSES"

echo "Found ${#IP_ARRAY[@]} IP addresses."

for ip in "${IP_ARRAY[@]}"; do
    ip=$(echo "$ip" | xargs)
    if ipset test "$IPSET_NAME" "$ip" &>/dev/null; then
        echo "IP $ip already exists in the set $IPSET_NAME, skipping."
    else
        echo "Add IP $ip to the set $IPSET_NAME."
        ipset add "$IPSET_NAME" "$ip"
    fi
done

ipset list "$IPSET_NAME"

ensure_iptables_rule nat PREROUTING -i "$LAN_IFACE" -p tcp -m set ! --match-set "$IPSET_NAME" dst -j REDIRECT --to-ports "$PORT"

ip rule add fwmark 5321 table 112 2>/dev/null || true
ip route add local 0.0.0.0/0 dev lo table 112 2>/dev/null || true
ensure_iptables_rule mangle PREROUTING -i "$LAN_IFACE" -p udp -m set ! --match-set "$IPSET_NAME" dst -j TPROXY --on-port "$PORT" --on-ip 127.0.0.1 --tproxy-mark 5321

sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.route_localnet=1
sysctl -w net.ipv4.conf."$LAN_IFACE".rp_filter=0
sysctl -w net.ipv4.ip_nonlocal_bind=1
