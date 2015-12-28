
# nshkmod

nshkmod is a Linux kernel module implementation of Network Service Header.
internet draft is https://tools.ietf.org/html/draft-ietf-sfc-nsh-01.

* Ehternet over NSH over VXLAN-GPE.
* Ethernet over NSH over Ethernet (ETHER_TYPE 0x894F)
* _nsh_ type interface: An nsh interface is an entry point to a path.
* SPI/SI, next-hop and transport mapping table in kernel space.
* packet encapsulation, decapsulation and tx/rx in kernel space.
* modified iproute2 package. You can configure the mapping via `ip nsh` command.

It is only tested on Ubuntu 14.04.3 trusty, kernel version 3.19.0-25-generic.

Note: this is absolutely experimental implementation.

## Compile and Install

compile and install nshkmod.ko

	 % git clone https://github.com/upa/nshkmod.git
	 % cd nshkmod
	 % make
	 % modprobe udp_tunnel
	 % insmod ./nshkmod.ko

compile modified iproute2 package

	 apt-get install libdb-dev flex bison xtables-addons-source
	 cd nshkmod/iproute2-3.19.0
	 ./configure
	 make
	 # then you can do ./ip/ip nsh
	 # and make install to /sbin/ip if you want.


## Design overview and How to use

An entry point for a path is an nsh interface. When xmit a packet to
an nsh interface, the packet is encapsulated into NSH headers (base
and path (and context if needed) headers). NSH encapsulated packets go
through look-up mapping table process. Look-up key of the table is
service path index and service index, and values of entries are next
hop IP address and encapsulation type _or_ nsh interface.


Received NSH packets from VXLAN newtorks are also processed in the
same manner. Outer headers up to VXLAN are removed, checking service
path index and service index, and received to an appropriate nsh
interface in accordance with the mapping table.

![overview](https://github.com/upa/nshkmod/raw/master/figs/overview.png)


By abstracting NSH paths as pseudo interfaces that means `struct
net_device`, existing Linux network stack and its various functions
can be used for network service chaining (e.g, Linux bridge,
openvswitch, openflow and IP routing, etc).


### Configuring nsh via `ip nsh` command

At first, create nsh interfaces.

	 % ip link add name nsh0 type nsh
	 % ifconfig nsh0
	 nsh0      Link encap:Ethernet  HWaddr be:2b:81:fb:34:0d
	           BROADCAST MULTICAST  MTU:1500  Metric:1
	           RX packets:0 errors:0 dropped:0 overruns:0 frame:0
	           TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
	           collisions:0 txqueuelen:0 
	           RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)
	 % ifconfig nsh0 up


Validate interface TX mapping by ip command. 'dev nshX none' means TX
of this interface is not mapped to any service path.

	 % ip nsh show dev
	 dev nsh0 none
	 %


Map TX to a service path. Then, transmitted packets through nsh0
interface are encapsulated in network service header with service path
index 10 and service index 5. Interface TX mapping can also be specified
when link creation and validated by `ip -d link show`.

	 % ip nsh set dev nsh0 spi 10 si 5
	 % ip nsh show dev
	 dev nsh0 spi 10 si 5
	 %
	 % ip link add name nsh1 type nsh spi 11 si 4
	 % ip nsh show dev
	 dev nsh0 spi 10 si 5
	 dev nsh1 spi 11 si 4
	 %
	 % ip -d link show dev nsh1
	 12: nsh1: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default
	     link/ether 86:74:9b:0d:8e:63 brd ff:ff:ff:ff:ff:ff promiscuity 0
	     nsh spi 11 si 4 addrgenmode eui64
	 %


Next, add a mapping table entry for the path. Then, transmitted
packets through nsh0 interface with network service header are
encapsulated again in VXLAN-GPE and transmitted to a remote host
10.0.0.2. Moreover, Ethernet over NSH over Ethernet is supported (vlan
is not supported).  When NSH is encapsulated in Ethernet header,
Ethertype is 0x894F. This number is assigned to Cisco vPath Network
Service Header in [IEEE Ethertype
assignment](http://standards-oui.ieee.org/ethertype/eth.txt), but used
for NSH in the draft. By the way, mdtype and vni can be
omitted. Default MD-type is 1 and vni is 0. Note that current
implementation does not consider vxlan VNI value.

	 % ip nsh add spi 10 si 5 encap vxlan remote 10.0.0.2 vni 10
	 % ip nsh add spi 11 si 4 mdtype 2 encap ether dst 08:00:27:93:f2:a7 link eth2
	 % ip nsh show
	 spi 11 si 4 mdtype 2 encap ether dst 08:01:27:93:f2:a7 link eth2
	 spi 10 si 5 mdtype 1 encap vxlan remote 10.0.0.2 vni 10
	 %

To delete mapping table entries, use `ip nsh del` with only `spi` and `si` arguments.


Finaly, interface RX should also be mapped to an other path. Serive path
is unidirectional.

	 % ip nsh add spi 12 si 4 dev nsh0
	 % ip nsh show
	 spi 12 si 4 mdtype 1 dev nsh0
	 spi 10 si 5 mdtype 1 remote 10.0.0.2 encap vxlan vni 10
	 %

[This pull request for tcpdump](https://github.com/the-tcpdump-group/tcpdump/pull/490)
enables to display NSH over VXLAN-GPE packets.

### Configuration example

#### 1. nsh interface chaining

nshkmod supports interface destination for service paths. By using this,
You can configure service paths in a host.

![inhostchain](https://github.com/upa/nshkmod/raw/master/figs/in-host-chain.png)

By changing bridge to other functions such as openvswitch or virtual machine,
a service function is inserted to the path.

- ip nsh commands
  - ip link add name nsh0 type nsh
  - ip link add name nsh1 type nsh
  - ip link add name nsh2 type nsh
  - ip link add name nsh3 type nsh
  - ip nsh add spi 3 si 2 dev nsh1
  - ip nsh add spi 3 si 1 dev nsh3
  - ip nsh add spi 4 si 2 dev nsh2
  - ip nsh add spi 4 si 1 dev nsh0
  - ip nsh set dev nsh0 spi 3 si 2
  - ip nsh set dev nsh1 spi 4 si 1
  - ip nsh set dev nsh2 spi 3 si 1
  - ip nsh set dev nsh3 spi 4 si 2



#### 2. multiple host chaining using VXLAN-GPE

![vxlanchain](https://github.com/upa/nshkmod/raw/master/figs/vxlan-chain.png)

- ip nsh commands at Host 1
  - ip link add name nsh0 type nsh
  - ip nsh set dev nsh0 spi 12 si 6
  - ip nsh add spi 12 si 6 remote HOST2 encap vxlan
  - ip nsh add spi 10 si 5 dev nsh0

- ip nsh commands at Host 2
  - ip link add name nsh0 type nsh
  - ip link add name nsh1 type nsh
  - ip nsh set dev nsh0 spi 10 si 5
  - ip nsh set dev nsh1 spi 12 si 5
  - ip nsh add spi 10 si 5 remote HOST1 encap vxlan
  - ip nsh add spi 12 si 6 dev nsh0
  - ip nsh add spi 12 si 5 remote HOST3 encap vxlan
  - ip nsh add spi 10 si 6 dev nsh1

- ip nsh commands at Host 3
  - ip link add name nsh0 type nsh
  - ip link set dev nsh0 spi 10 si 6
  - ip nsh add spi 10 si 6 remote HOST2 encap vxlan
  - ip nsh add spi 12 si 5 dev nsh0


## Contact
upa@haeena.net
