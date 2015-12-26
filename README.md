
# nshkmod

nshkmod is an implementation of Network Service Header.
internet draft is https://tools.ietf.org/html/draft-ietf-sfc-nsh-01.

nshkmod is Linux kernel module. It provides
* Ehternet over NSH over VXLAN-GPE,
* _nsh_ type interface: An nsh interface is an entry point to a path.
* SPI/SI, next-hop, transport mapping table in kernel space.
* packet encapsulation, decapsulation, tx/rx in kernel space.
* modified iproute2 package. You can configure the mapping via `ip nsh` command.

It is only tested on Ubuntu 14.04.3 trusty, kernel version 3.19.0-25-generic.


## compile and install

compile and install nshkmod.ko

	 git clone https://github.com/upa/nshkmod.git
	 cd nshkmod
	 make
	 modprobe udp_tunnel
	 insmod ./nshkmod.ko

compile modified iproute2 package

	 apt-get install libdb-dev flex bison xtables-addons-source
	 cd nshkmod/iproute2-3.19.0
	 ./configure
	 make
	 # then you can do ./ip/ip nsh
	 # and make install to /sbin/ip if you want.


## design and how to use



## contact
upa@haeena.net
