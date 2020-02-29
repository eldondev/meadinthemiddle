set -xuo pipefail
go build .
sudo ip netns add meadns
sudo brctl addbr testmead0
sudo ip link add meadeth0 type veth peer meadeth1
sudo ip link set meadeth1 netns meadns
sudo brctl addif testmead0 meadeth0
sudo ip tuntap add tap0 user `whoami` mode tap
sudo brctl addif testmead0 tap0
sudo ip link set testmead0 up
sudo ip link set tap0 up
sudo ip link set meadeth0 up
sudo ip netns exec meadns ip link set meadeth1 up
sudo ip netns exec meadns ip addr add 10.0.0.2/24 dev meadeth1
sudo ip netns exec meadns route add default gw 10.0.0.1
sudo timeout 30 wireshark -i tap0 -k & sleep 1
timeout 30 ./meadtap -tap tap0 10.0.0.1 443 & ( sleep 1 && sudo ip netns exec meadns curl -kvv https://eldondev.com )
wait
sudo ip tuntap del tap0 mode tap
sudo ip link delete meadeth0
sudo ip link set testmead0 down
sudo brctl delbr testmead0
sudo ip netns delete meadns
