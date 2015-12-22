/* nshkmod.c 
 * nsh kernel module implementation.
 * based on https://tools.ietf.org/html/draft-ietf-sfc-nsh-01
 */


#ifndef DEBUG
#define DEBUG
#endif

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/rculist.h>
#include <linux/hash.h>
#include <linux/udp.h>
#include <net/protocol.h>
#include <net/udp.h>
#include <net/sock.h>
#include <net/route.h>
#include <net/ip6_route.h>
#include <net/vxlan.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/rtnetlink.h>
#include <net/genetlink.h>


#include "nshkmod.h"

#define NSHKMOD_VERSION "0.0"
MODULE_VERSION (NSHKMOD_VERSION);
MODULE_LICENSE ("GPL");
MODULE_AUTHOR ("upa@haeena.net");
MODULE_DESCRIPTION ("network service header kernel module implementation");

#define PRNSH	"nshkmod: "

#define NSH_VXLAN_PORT	60000
#define NSH_VXLAN_IPV4_HEADROOM	(16 + 8 + 16 + 16) /* UDP+VXLAN+NSH-MD1*/


static int nshkmod_net_id;
static u32 nshkmod_salt __read_mostly;


/* Pseudo network device */
struct nsh_dev {
	struct list_head	list;	/* nsh_net->dev_list */
	struct rcu_head		rcu;

	struct net 		* net;
	struct net_device	* dev;

	__u32	key;	/* SPI+SI. 0 means not assigned  */
	__u32	sp;	/* service path index */
	__u8	si;	/* service index */
};
#define nsh_key_by_spi_si(key, spi, si)\
	do {					\
		(key |= spi) <<= 8;		\
		key |= si;			\
	} while (0)

/* remote node (next node of the path) infromation */
struct nsh_dst {
	__u8	enca_type;
	__u32	vni;		/* vni for vxlan encap */
	__be32	remote_ip;	/* XXX: should support IPv6 */
};

/* nsh_table entry. SPI+SI -> Dst (dev or remote) */
struct nsh_table {
	struct hlist_node	hlist;	/* linked list of hashtable */
	struct rcu_head		rcu;
	struct net		* net;
	unsigned long		updated;	/* jiffies */


	__u32	key;	/* SPI+SI */
	__u32	spi;	/* service path index */
	__u8	si;	/* service index */

	struct nsh_dev	* rdev;
	struct nsh_dst	* rdst;
};

/* per net_namespace structure */
struct nsh_net {
#define NSH_HASH_SIZE	(1<< 8)	
	struct hlist_head	nsh_table[NSH_HASH_SIZE]; /* nsh_table hash */
	struct list_head	dev_list;	/* nsh_dev list*/
	struct vxlan_sock	* vs;		/* vxlan socket */
};


void
vxlan_rcv (struct vxlan_sock * vs, struct sk_buff * skb, __be32 key)
{
	/* TODO: */
	return;
}


static const struct net_device_ops nsh_netdev_ops = {
	
};


/* info for netdev */
static struct device_type nsh_type = {
	.name = "nsh",
};

/* initialize the device structure */
static void
nsh_setup (struct net_device * dev)
{
	struct nsh_dev * ndev = netdev_priv (dev);

	eth_hw_addr_random (dev);
	ether_setup (dev);
	dev->needed_headroom = ETH_HLEN + NSH_VXLAN_IPV4_HEADROOM; /* XXX */

	dev->netdev_ops = &nsh_netdev_ops;
	dev->destructor = free_netdev;
	SET_NETDEV_DEVTYPE (dev, &nsh_type);

	dev->tx_queue_len = 0;
	dev->features	|= NETIF_F_LLTX;
	dev->features	|= NETIF_F_NETNS_LOCAL;
	netif_keep_dst(dev);
	dev->priv_flags |= IFF_LIVE_ADDR_CHANGE;

	INIT_LIST_HEAD (&ndev->list);

	ndev->dev = dev;
	ndev->key = 0;
	ndev->si = 0;

	return;
}

static int
nsh_newlink (struct net * net, struct net_device * dev,
	     struct nlattr *tb [], struct nlattr * data[])
{
	/* XXX: path,destination and device mapping is done after link
	 * creation by generic netlink and iproute2. newlink only does
	 * register_netdevice. */

	int err;
	struct nsh_net * nnet = net_generic (net, nshkmod_net_id);
	struct nsh_dev * ndev = netdev_priv (dev);

	ndev->net = net;

	err = register_netdevice (dev);
	if (err) {
		printk (KERN_ERR PRNSH "failed to register netdevice\n");
		return err;
	}

	list_add_tail_rcu (&ndev->list, &nnet->dev_list);

	return 0;
}

static void
nsh_dellink (struct net_device * dev, struct list_head * head)
{
	unsigned int n;
	struct nsh_dev * ndev = netdev_priv (dev);
	struct nsh_net * nnet = net_generic (ndev->net, nshkmod_net_id);

	/* remove this device from nsh table */
	for (n = 0; n < NSH_HASH_SIZE; n++) {
		struct nsh_table * nt;		

		hlist_for_each_entry_rcu (nt, &nnet->nsh_table[n], hlist) {
			if (nt->rdev == ndev)
				nt->rdev = NULL;
		}
	}
	
	list_del_rcu (&ndev->list);
	unregister_netdevice_queue (dev, head);

	return;
}

static struct rtnl_link_ops nshkmod_link_ops __read_mostly = {
	.kind		= "nsh",
	.maxtype	= 0,
	.priv_size	= sizeof (struct nsh_dev),
	.setup		= nsh_setup,
	.newlink	= nsh_newlink,
	.dellink	= nsh_dellink,
};

static __net_init int
nshkmod_init_net (struct net * net)
{
	unsigned int n;
	struct nsh_net * nnet = net_generic (net, nshkmod_net_id);
		
	for (n = 0; n < NSH_HASH_SIZE; n++)
		INIT_HLIST_HEAD (&nnet->nsh_table[n]);

	INIT_LIST_HEAD (&nnet->dev_list);

	nnet->vs = vxlan_sock_add (net, NSH_VXLAN_PORT, vxlan_rcv, NULL,
				   true, 0);
	if (IS_ERR (nnet->vs)) {
		printk (KERN_ERR PRNSH "failed to add vxlan socket\n");
		return -EINVAL;
	}

	printk (KERN_INFO PRNSH "nsh kmod version %s loaded\n",
		NSHKMOD_VERSION);

	return 0;
}

static void __net_exit
nshkmod_exit_net (struct net * net)
{
	struct nsh_net * nnet = net_generic (net, nshkmod_net_id);
	struct nsh_dev * ndev, * next;
	struct net_device * dev, * aux;
	LIST_HEAD (list);

	rtnl_lock ();
	for_each_netdev_safe (net, dev, aux)
		if (dev->rtnl_link_ops == &nshkmod_link_ops)
			unregister_netdevice_queue (dev, &list);

	list_for_each_entry_safe (ndev, next, &nnet->dev_list, list) {
		if (!net_eq (dev_net (ndev->dev), net))
			unregister_netdevice_queue (ndev->dev, &list);
	}
	rtnl_unlock ();

	/* TODO: destroy all nsh_dst and nsh_able */

	vxlan_sock_release (nnet->vs);

	printk (KERN_INFO PRNSH "nsh kmod version %s unloaded\n",
		NSHKMOD_VERSION);

	return;
}

static struct pernet_operations nshkmod_net_ops = {
	.init	= nshkmod_init_net,
	.exit	= nshkmod_exit_net,
	.id	= &nshkmod_net_id,
	.size	= sizeof (struct nsh_net),
};

static int __init
nshkmod_init_module (void)
{
	int rc;

	get_random_bytes (&nshkmod_salt, sizeof (nshkmod_salt));

	rc = register_pernet_subsys (&nshkmod_net_ops);
	if (rc)
		goto out;

	rc = rtnl_link_register (&nshkmod_link_ops);
	if (rc)
		goto rtnl_failed;

rtnl_failed:
	unregister_pernet_subsys (&nshkmod_net_ops);
out:
	return rc;
}
module_init (nshkmod_init_module);

static void __exit
nshkmod_exit_module (void)
{
	return;
}
module_exit (nshkmod_exit_module);
