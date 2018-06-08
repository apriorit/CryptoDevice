NETWORK_INTERFACE=$1
BRIDGE_NAME=qemu_br0

if [ -z "$1" ]; then
    ip a
    echo "ARG - network interface"
    exit 1
fi

TAP_NAME=`tunctl -b`

ip link add $BRIDGE_NAME type bridge || exit 1
echo "BRIDGE=$BRIDGE_NAME"

ip addr flush dev $NETWORK_INTERFACE || exit 1
echo "Flush $NETWORK_INTERFACE"

ip link set $NETWORK_INTERFACE master $BRIDGE_NAME || exit 1
echo "$NETWORK_INTERFACE added to $BRIDGE_NAME"

ip link set $TAP_NAME master $BRIDGE_NAME || exit 1
echo "$TAP_NAME added to $BRIDGE_NAME"

ip link set dev $BRIDGE_NAME up || exit 1
ip link set dev $TAP_NAME up || exit 1
echo "Devs $BRIDGE_NAME and $TAP_NAME UP is done"

dhclient $BRIDGE_NAME || exit 1
echo "DHCP $BRIDGE_NAME is done"


