SHELL=/bin/bash

ifeq ($(DEBUG),1)
  DEBUG := 1
else
  DEBUG := 0
endif

ifeq ($(VERBOSE),1)
  QUIET :=
else
  QUIET := @
endif

#ETHTOOL_OPTS := tso off gso off gro off ufo off tx-gso-list off scatter-gather off tx-udp-segmentation off tx-gre-segmentation off tx-gre-csum-segmentation off tx-ipxip4-segmentation off tx-ipxip6-segmentation off tx-udp_tnl-segmentation off tx-udp_tnl-csum-segmentation off
ETHTOOL_OPTS := rx-checksumming off tx-checksumming off
MTU := 1440 #To be on the safe side
CLANG ?= clang

IPERF_OPTS := -u -b 10G -l 1400
IPERF_SERVER_OPTS := -u

all: check
check: _setup _load

##
## Test scenario
#
#  NS1                                         NS2
#  ...........                        ............
#  .  -----  .   -----        -----   .  -----   .
#  . |veth0|<-->|veth1|      |veth2|<-->|veth3|  .
#  .  -----  .   -----        -----   .  -----   .
#  ...........                        ............
#

_setup:
	$(QUIET)echo -n "Creating ifaces..."
	$(QUIET)sudo ip link add type veth
	$(QUIET)sudo ip link add type veth
	$(QUIET)echo "OK"
	$(QUIET)echo -n "Creating ns1, ns2..."
	$(QUIET)sudo ip netns add ns1
	$(QUIET)sudo ip netns add ns2
	$(QUIET)echo "OK"
	$(QUIET)echo -n "Moving: eth0=>ns1, eth3=>n2..."
	$(QUIET)sudo ip link set netns ns1 dev veth0
	$(QUIET)sudo ip link set netns ns2 dev veth3
	$(QUIET)echo "OK"
	$(QUIET)echo -n "Disable TSO..."
	$(QUIET)sudo ip netns exec ns1 ethtool -K veth0 $(ETHTOOL_OPTS)
	$(QUIET)sudo ethtool -K veth1 $(ETHTOOL_OPTS)
	$(QUIET)sudo ethtool -K veth2 $(ETHTOOL_OPTS)
	$(QUIET)sudo ip netns exec ns2 ethtool -K veth3 $(ETHTOOL_OPTS)
	$(QUIET)sudo ip netns exec ns2 ethtool --show-offload veth3
	$(QUIET)echo "OK"
	$(QUIET)echo -n "Bringing them up..."
	$(QUIET)sudo ip link set up dev veth1
	$(QUIET)sudo ip link set up dev veth2
	$(QUIET)sudo ip netns exec ns1 ip link set up dev lo
	$(QUIET)sudo ip netns exec ns2 ip link set up dev lo
	$(QUIET)sudo ip netns exec ns1 ip link set up dev veth0
	$(QUIET)sudo ip netns exec ns2 ip link set up dev veth3
	$(QUIET)echo "OK"
	$(QUIET)echo -n "Setting MTU..."
	$(QUIET)sudo ip netns exec ns1 ip link set mtu $(MTU) dev veth0
	$(QUIET)sudo ip netns exec ns2 ip link set mtu $(MTU) dev veth3
	$(QUIET)echo "OK"
	$(QUIET)echo -n "Add IP addresses..."
	$(QUIET)sudo ip netns exec ns1 ip addr add 10.0.0.1/24 dev veth0
	$(QUIET)sudo ip addr add 10.0.0.2/24 dev veth1
	$(QUIET)sudo ip addr add 10.0.1.1/24 dev veth2
	$(QUIET)sudo ip netns exec ns2 ip addr add 10.0.1.2/24 dev veth3
	$(QUIET)echo "OK"
	$(QUIET)echo -n "Add default routes to NSs..."
	$(QUIET)sudo ip netns exec ns1 ip route add default via 10.0.0.2
	$(QUIET)sudo ip netns exec ns2 ip route add default via 10.0.1.1
	$(QUIET)echo "OK"
	$(QUIET)echo -n "Open the firewall..."
	$(QUIET)sudo iptables -I FORWARD -d 10.0.0.0/8 -j ACCEPT
	$(QUIET)echo "OK"
	$(QUIET)echo -n "Disable RPF filters..."
	$(QUIET)sudo ip netns exec ns1 sysctl -q net.ipv4.conf.veth0.rp_filter=0
	$(QUIET)sudo sysctl -q net.ipv4.conf.veth1.rp_filter=0
	$(QUIET)sudo sysctl -q net.ipv4.conf.veth2.rp_filter=0
	$(QUIET)sudo ip netns exec ns2 sysctl -q net.ipv4.conf.veth3.rp_filter=0
	$(QUIET)echo "OK"
	$(QUIET)echo -n "Test base setup..."
	$(QUIET)sudo ip netns exec ns1 ping -c 1 10.0.1.2 > /dev/null
	$(QUIET)echo "OK"

_compile:
	cd ../src && $(MAKE)

_load: _compile
	$(QUIET)sudo ip netns exec ns1 tc qdisc add dev veth0 clsact
	$(QUIET)sudo ip netns exec ns1 tc filter add dev veth0 egress bpf da obj ../src/push.o verbose
	$(QUIET)sudo tc qdisc add dev veth2 clsact
	$(QUIET)sudo tc filter add dev veth2 egress bpf da obj ../src/pop.o verbose
	#$(QUIET)sudo ip netns exec ns2 tc qdisc add dev veth3 clsact
	#$(QUIET)sudo ip netns exec ns2 tc filter add dev veth3 ingress bpf da obj ../src/pop.o verbose

_unload:
	$(QUIET)sudo ip netns exec ns1 tc filter del dev veth0 egress
	$(QUIET)sudo ip netns exec ns2 tc filter del dev veth0 ingress

_clean_iperf:
	$(QUIET)sudo ip netns exec ns1 killall iperf || true
	$(QUIET)sudo ip netns exec ns2 killall iperf || true

# No DNAT/SNAT
check_perf_calibration:
	$(QUIET)sudo ip netns exec ns2 iperf -s -p 80 $(IPERF_SERVER_OPTS) &
	$(QUIET)sudo ip netns exec ns1 iperf -c 10.0.1.2 -p 80 $(IPERF_OPTS)
	$(QUIET) $(MAKE) _clean_iperf
check_perf:
	$(QUIET)sudo ip netns exec ns2 iperf -s -p 8080 $(IPERF_SERVER_OPTS) &
	$(QUIET)sudo ip netns exec ns1 iperf -c 10.0.1.2 -p 8080 $(IPERF_OPTS)
	$(QUIET) $(MAKE) _clean_iperf

clean: _clean_iperf
	$(QUIET)sudo iptables -D FORWARD -d 10.0.0.0/8 -j ACCEPT || true
	$(QUIET)sudo ip link del veth1 || true
	$(QUIET)sudo ip link del veth2 || true
	$(QUIET)sudo ip netns del ns1 || true
	$(QUIET)sudo ip netns del ns2 || true
