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
#include <net/udp_tunnel.h>
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

	/* XXX: nsh_net->nsh_table[n] should be locked when add or delete */
};

/* per net_namespace structure */
struct nsh_net {
	struct net	* net;

#define NSH_HASH_BITS	8
#define NSH_HASH_SIZE	(1 << NSH_HASH_BITS)
	struct hlist_head	nsh_table[NSH_HASH_SIZE]; /* nsh_table hash */
	struct list_head	dev_list;	/* nsh_dev list*/
	struct socket		* sock;		/* udp tunnel socket */
};


static inline struct hlist_head *
nsh_table_head (struct nsh_net * nnet, __u32 key) {
	return &nnet->nsh_table[hash_32 (key, NSH_HASH_BITS)];
}

static struct nsh_table *
nsh_find_table (struct nsh_net * nnet, __u32 key)
{
	struct hlist_head * head = nsh_table_head (nnet, key);
	struct nsh_table * nt;

	hlist_for_each_entry_rcu (nt, head, hlist) {
		if (key == nt->key)
			return nt;
	}

	return NULL;
}

static int
nsh_add_table (struct nsh_net * nnet, __u32 key, struct nsh_dev * rdev,
	       struct nsh_dst * rdst)
{
	struct nsh_table * nt;

	nt = kmalloc (sizeof (*nt), GFP_KERNEL);
	if (!nt) {
		pr_debug (PRNSH "%s:fail to alloc memory ", __func__);
		return -ENOMEM;
	}
	memset (nt, 0, sizeof (*nt));

	nt->net	= nnet->net;
	nt->key = key;
	nt->spi = key >> 8;
	nt->si	= key & 0x000000FF;
	nt->rdev = rdev;
	nt->rdst = rdst;	/* which one (rdev or rdst) must be NULL */

	hlist_add_head_rcu (&nt->hlist, nsh_table_head (nnet, key));

	return 0;
}

static void
nsh_delete_table (struct nsh_table * nt)
{
	hlist_del_rcu (&nt->hlist);
	kfree_rcu (nt, rcu);
}

static void
nsh_free_table (struct rcu_head * head)
{
	struct nsh_table * nt = container_of (head, struct nsh_table, rcu);

	if (nt->rdst)
		kfree (nt->rdst);
	kfree (nt);

	return;
}

static void
nsh_destroy_table (struct nsh_net * nnet)
{
	unsigned int n;

	for (n = 0; n < NSH_HASH_SIZE; n++) {
		struct hlist_node * ptr, * tmp;

		hlist_for_each_safe (ptr, tmp, &nnet->nsh_table[n]) {
			struct nsh_table * nt;

			nt = container_of (ptr, struct nsh_table, hlist);
			hlist_del_rcu (&nt->hlist);
			call_rcu (&nt->rcu, nsh_free_table);
		}
	}

	return;
}

static netdev_tx_t
nsh_xmit (struct sk_buff * skb, struct net_device * dev)
{
	/* TODO: */
	return NETDEV_TX_OK;
}

static int
nsh_vxlan_udp_encap_recv (struct sock * sk, struct sk_buff * skb)
{
	/* TODO: */
	return 0;
}

/* setup stats when device is created */
static int
nsh_init (struct net_device * dev)
{
	dev->tstats = netdev_alloc_pcpu_stats (struct pcpu_sw_netstats);
	if (!dev->tstats)
		return -ENOMEM;

	return 0;
}

static void
nsh_uninit (struct net_device * dev)
{
	free_percpu (dev->tstats);
}

static int
nsh_open (struct net_device * dev)
{
	/* XXX: validation needed? */
	return 0;
}

static int
nsh_stop (struct net_device * dev)
{
	/* nothing to be done. */
	return 0;
}

static const struct net_device_ops nsh_netdev_ops = {
	.ndo_init		= nsh_init,
	.ndo_uninit		= nsh_uninit,
	.ndo_open		= nsh_open,
	.ndo_stop		= nsh_stop,
	.ndo_start_xmit	       	= nsh_xmit,
	.ndo_get_stats64	= ip_tunnel_get_stats64,
	.ndo_change_mtu		= eth_change_mtu,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_set_mac_address	= eth_mac_addr,
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

static struct socket *
nsh_vxlan_create_sock (struct net * net, __be16 port)
{
	/* XXX: vxlan_skb_xmit does have API to configure flags in
	 * vxlan header (kernel 3.19) that is needed for VXLAN-GPE.
	 * So, normal udp socket and udp_tunnel_xmit are used. */

	int err;
	struct socket * sock;
	struct udp_port_cfg udp_conf;
	struct udp_tunnel_sock_cfg tunnel_cfg;

	memset (&udp_conf, 0, sizeof (udp_conf));

	/* XXX: should support IPv6 */
	udp_conf.family = AF_INET;
	udp_conf.local_ip.s_addr = INADDR_ANY;
	udp_conf.local_udp_port = port;

	err = udp_sock_create (net, &udp_conf, &sock);
	if (err < 0)
		return ERR_PTR (err);

	tunnel_cfg.encap_type = 1;
	tunnel_cfg.encap_rcv = nsh_vxlan_udp_encap_recv;
	tunnel_cfg.encap_destroy = NULL;
	setup_udp_tunnel_sock (net, sock, &tunnel_cfg);

	return sock;
}

static __net_init int
nshkmod_init_net (struct net * net)
{
	unsigned int n;
	struct nsh_net * nnet = net_generic (net, nshkmod_net_id);
		
	for (n = 0; n < NSH_HASH_SIZE; n++)
		INIT_HLIST_HEAD (&nnet->nsh_table[n]);

	INIT_LIST_HEAD (&nnet->dev_list);
	nnet->net = net;

	nnet->sock = nsh_vxlan_create_sock (net, htons (NSH_VXLAN_PORT));
	if (IS_ERR (nnet->sock)) {
		printk (KERN_ERR PRNSH "failed to add vxlan udp socket\n");
		return -EINVAL;
	}

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

	nsh_destroy_table (nnet);

	udp_tunnel_sock_release (nnet->sock);

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
		goto netns_failed;

	rc = rtnl_link_register (&nshkmod_link_ops);
	if (rc)
		goto rtnl_failed;

	printk (KERN_INFO PRNSH "nsh kmod version %s loaded\n",
		NSHKMOD_VERSION);

	return 0;

rtnl_failed:
	unregister_pernet_subsys (&nshkmod_net_ops);
netns_failed:
	return rc;
}
module_init (nshkmod_init_module);

static void __exit
nshkmod_exit_module (void)
{
	rtnl_link_unregister (&nshkmod_link_ops);
	unregister_pernet_subsys (&nshkmod_net_ops);

	printk (KERN_INFO PRNSH "nsh kmod version %s unloaded\n",
		NSHKMOD_VERSION);

	return;
}
module_exit (nshkmod_exit_module);
