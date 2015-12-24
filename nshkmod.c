/* nshkmod.c 
 * NSH kernel module implementation.
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

/*
 *
 * Network Service Header format.
 * https://tools.ietf.org/html/draft-ietf-sfc-nsh-01
 *
 * Base Heder
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Ver|O|C|R|R|R|R|R|R|   Length  |    MD Type    | Next Protocol |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Service Path Header
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          Service Path ID                      | Service Index |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * MD-type 1, four Context Header, 4-byt each.
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                Mandatory Context Header                       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                Mandatory Context Header                       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                Mandatory Context Header                       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                Mandatory Context Header                       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *
 * It only supports MD-type 1 and MD-type 2 with 0 byte (No) Conetxt
 * header and Ethernet for next protocol (rtnl_link_ops).
 *
 */

struct nsh_base_hdr {
	__u8	flags;	/* Ver, O, C, Rx4 */
	__u8	length;	/* Rx2, Length*/
	__u8	mdtype;
	__u8	protocol;
};
#define NSH_BASE_CHECK_VERSION(f, v) (((f) & 0xC0) == v)
#define NSH_BASE_OAM(f) ((f) & 0x20)
#define NSH_BASE_CRITCAL(f) ((f) & 0x10)
#define NSH_BASE_LENGTH(l) ((l) & 0x3F)

#define NSH_BASE_MDTYPE1	0x01
#define NSH_BASE_MDTYPE2	0x02

#define NSH_BASE_PROTO_IPV4	0x01	/* XXX: not supported */
#define NSH_BASE_PROTO_IPV6	0x02	/* XXX: not supported */
#define NSH_BASE_PROTO_ETH	0x03


struct nsh_path_hdr {
	__be32 spisi;	/* SPI + SI */
};

struct nsh_ctx_type1 {
	__be32	ctx[4];
};

struct nsh_vlm_hdr {
	__be16	class;
	__u8	type;	/* 1st bit is C */
	__u8	length;	/* first 3 bits are reserved */
};

#define NSHKMOD_VERSION "0.0"
MODULE_VERSION (NSHKMOD_VERSION);
MODULE_LICENSE ("GPL");
MODULE_AUTHOR ("upa@haeena.net");
MODULE_DESCRIPTION ("network service header kernel module implementation");

#define PRNSH	"nshkmod: "

#define VXLAN_HLEN	(sizeof (struct vxlanhdr) + sizeof (struct udphdr))
#define NSH_MDTYPE2_0_HLEN	(sizeof (struct nsh_base_hdr) + \
				 sizeof (struct nsh_path_hdr))

#define NSH_VXLAN_PORT	60000
#define NSH_VXLAN_IPV4_HEADROOM	(16 + 8 + 16 + 16) /* UDP+VXLAN+NSH-MD1*/
#define NSH_VXLAN_TTL	64

#define VXLAN_GPE_FLAGS 0x0C000000	/* set next protocol */
#define VXLAN_GPE_PROTO_IPV4	0x01
#define VXLAN_GPE_PROTO_IPV6	0x02
#define VXLAN_GPE_PROTO_ETH	0x03
#define VXLAN_GPE_PROTO_NSH	0x04
#define VXLAN_GPE_PROTO_MPLS	0x05


static int nsh_net_id;
static u32 nshkmod_salt __read_mostly;


/* Pseudo network device */
struct nsh_dev {
	struct list_head	list;	/* nsh_net->dev_list */
	struct rcu_head		rcu;

	struct net_device	* dev;

	__be32	key;	/* SPI+SI. 0 means not assigned  */
};

/* remote node (next node of the path) infromation */
struct nsh_dst {
	__u8	encap_type;
	__be32	remote_ip;	/* XXX: should support IPv6 */
	__be32	local_ip;	/* XXX: sould support IPv6 */
	__be32	vni;		/* vni for vxlan encap */
};

/* nsh_table entry. SPI+SI -> Dst (dev or remote) */
struct nsh_table {
	struct hlist_node	hlist;	/* linked list of hashtable */
	struct rcu_head		rcu;
	struct net		* net;
	unsigned long		updated;	/* jiffies */


	__be32	key;	/* SPI+SI */
	__be32	spi;	/* service path index */
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
nsh_table_head (struct nsh_net * nnet, __be32 key) {
	return &nnet->nsh_table[hash_32 (key, NSH_HASH_BITS)];
}

static struct nsh_table *
nsh_find_table (struct nsh_net * nnet, __be32 key)
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
nsh_add_table (struct nsh_net * nnet, __be32 key, struct nsh_dev * rdev,
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
nsh_free_table (struct rcu_head * head)
{
	struct nsh_table * nt = container_of (head, struct nsh_table, rcu);

	if (nt->rdst)
		kfree (nt->rdst);
	kfree (nt);

	return;
}

static void
nsh_delete_table (struct nsh_table * nt)
{
	hlist_del_rcu (&nt->hlist);
	call_rcu (&nt->rcu, nsh_free_table);
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
			nsh_delete_table (nt);
		}
	}

	return;
}

static int
nsh_recv (struct sk_buff * skb)
{
	int hdrlen;
	struct nsh_base_hdr * nbh;
	struct nsh_path_hdr * nph;
	struct nsh_table * nt;
	struct nsh_net * nnet = net_generic (sock_net (skb->sk), nsh_net_id);
	struct pcpu_sw_netstats * stats;

	nbh = (struct nsh_base_hdr *) skb->data;
	nph = (struct nsh_path_hdr *) (nbh + 1);

	if (unlikely (!NSH_BASE_CHECK_VERSION (nbh->flags, 0))) {
		pr_debug (PRNSH "invalid nsh version flag %#x\n", nbh->flags);
		return -1;
	}
	if (NSH_BASE_OAM (nbh->flags)) {
		pr_debug (PRNSH "oam is not supported %#x\n", nbh->flags);
		return -1;
	}
	/* XXX: C bit should be considered on software? */

	nt = nsh_find_table (nnet, nph->spisi);
	if (!nt | !nt->rdev) {
		return -1;
	}

	hdrlen = NSH_BASE_LENGTH (nbh->length) << 2;
	__skb_pull (skb, hdrlen);
	skb_reset_mac_header (skb);
	skb->protocol = eth_type_trans (skb, nt->rdev->dev);
	skb->encapsulation = 0;
	skb_reset_network_header (skb);


	stats = this_cpu_ptr (nt->rdev->dev->tstats);
	u64_stats_update_begin (&stats->syncp);
	stats->rx_packets++;
	stats->rx_bytes++;
	u64_stats_update_end (&stats->syncp);

	netif_rx (skb);

	return 0;
}

static int
nsh_vxlan_udp_encap_recv (struct sock * sk, struct sk_buff * skb)
{
	/* pop udp and vxlan header. checking spi si and forwarding to
	 * appropriate interface are done by nsh_recv (outer
	 * encapsulation protocol independent). */

	struct vxlanhdr * vxh;

	if (!pskb_may_pull (skb, VXLAN_HLEN))
		goto err;

	vxh = (struct vxlanhdr *) (udp_hdr (skb) + 1);
	if (vxh->vx_flags != (VXLAN_GPE_FLAGS | VXLAN_GPE_PROTO_NSH)) {
		netdev_dbg (skb->dev, "invalid vxlan flags %#x\n",
			    ntohl (vxh->vx_flags));
		goto err;
	}

	__skb_pull (skb, VXLAN_HLEN);

	return nsh_recv (skb);

err:
	return 1;
}

static netdev_tx_t
nsh_xmit_vxlan (struct sk_buff * skb, struct nsh_net * nnet,
		struct nsh_dev * ndev, struct nsh_table * nt)
{
	int err;
	struct flowi4 fl4;
	struct rtable * rt;
	struct vxlanhdr * vxh;

	memset (&fl4, 0, sizeof (fl4));
	fl4.daddr = nt->rdst->remote_ip;
	fl4.saddr = nt->rdst->local_ip;

	rt = ip_route_output_key (dev_net (ndev->dev), &fl4);
	if (IS_ERR (rt)) {
		netdev_dbg (ndev->dev, "no route found to %pI4\n",
			    (struct in_addr *)&nt->rdst->remote_ip);
		ndev->dev->stats.tx_carrier_errors++;
		ndev->dev->stats.tx_dropped++;
		return -NETDEV_TX_OK;
	}

	err = skb_cow_head (skb, NSH_VXLAN_IPV4_HEADROOM);
	if (unlikely (err)) {
		kfree_skb (skb);
		return -NETDEV_TX_OK;
	}

	vxh = (struct vxlanhdr *) __skb_push (skb, sizeof (*vxh));
	vxh->vx_flags = htonl (VXLAN_GPE_FLAGS | VXLAN_GPE_PROTO_NSH);
	vxh->vx_vni = nt->rdst->vni;

	return udp_tunnel_xmit_skb (nnet->sock, rt, skb, nt->rdst->local_ip,
				    nt->rdst->remote_ip, 0, NSH_VXLAN_TTL, 0,
				    NSH_VXLAN_PORT, NSH_VXLAN_PORT, nnet->net);
}

static netdev_tx_t
nsh_xmit (struct sk_buff * skb, struct net_device * dev)
{
	int rc;
	struct pcpu_sw_netstats * tx_stats;
	struct nsh_dev * ndev = netdev_priv (dev);
	struct nsh_net * nnet = net_generic (dev_net (dev), nsh_net_id);
	struct nsh_table * nt;
	struct nsh_base_hdr * nbh;
	struct nsh_path_hdr * nph;

	nt = nsh_find_table (nnet, ndev->key);
	if (!nt) {
		if (net_ratelimit ())
			netdev_dbg (dev, "path is not assigned\n");
		goto tx_err;
	}

	if (nt->rdev) {
		/* nexthop is nsh interface in this machine. */
		nsh_recv (skb);
		goto update_stats;
	}

	if (nt->rdst) {
		switch (nt->rdst->encap_type) {
		case NSH_ENCAP_TYPE_VXLAN :
			rc = nsh_xmit_vxlan (skb, nnet, ndev, nt);
			break;
		default :
			netdev_dbg (dev, "invalid encap type %d\n",
				    nt->rdst->encap_type);
			goto tx_err;
		}
	}

	/* add NSH MD-TYPE 2 without metadata */
	rc = skb_cow_head (skb, NSH_MDTYPE2_0_HLEN);
	if (unlikely (rc)) {
		netdev_dbg (dev, "failed to skb_cow_head\n");
		kfree_skb (skb);
		goto tx_err;
	}

	nbh = (struct nsh_base_hdr *) __skb_push (skb, sizeof (*nbh));
	nbh->flags	= 0;
	nbh->length	= NSH_MDTYPE2_0_HLEN >> 2;	/* 4byte word */
	nbh->mdtype	= NSH_BASE_MDTYPE2;
	nbh->protocol	= NSH_BASE_PROTO_ETH;

	nph = (struct nsh_path_hdr *) __skb_push (skb, sizeof (*nph));
	nph->spisi = ndev->key;

	rc = nsh_xmit_vxlan (skb, nnet, ndev, nt);
	if (rc != NETDEV_TX_OK)
		goto tx_err;

update_stats:
	u64_stats_update_begin (&tx_stats->syncp);
	tx_stats->tx_packets++;
	tx_stats->tx_bytes += skb->len;
	u64_stats_update_end (&tx_stats->syncp);

	return NETDEV_TX_OK;

tx_err:
	dev->stats.tx_errors++;

	return NETDEV_TX_OK;
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

	return;
}

static int
nsh_newlink (struct net * net, struct net_device * dev,
	     struct nlattr *tb [], struct nlattr * data[])
{
	/* XXX: path, destination and device mapping is configured by
	 * user or orchestrator through generic netlink after link
	 * creation. so, newlink only does register_netdevice. */

	int err;
	struct nsh_net * nnet = net_generic (net, nsh_net_id);
	struct nsh_dev * ndev = netdev_priv (dev);

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
	struct nsh_net * nnet = net_generic (dev_net (dev), nsh_net_id);

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
	/* XXX: vxlan_skb_xmit does not have API to configure flags in
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
	struct nsh_net * nnet = net_generic (net, nsh_net_id);
		
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
	struct nsh_net * nnet = net_generic (net, nsh_net_id);
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
	.id	= &nsh_net_id,
	.size	= sizeof (struct nsh_net),
};


static struct genl_family nshkmod_nl_family = {
	.id		= GENL_ID_GENERATE,
	.name		= NSHKMOD_GENL_NAME,
	.version	= NSHKMOD_GENL_VERSION,
	.maxattr	= NSHKMOD_ATTR_MAX,
	.hdrsize	= 0,
};

static struct nla_policy nshkmod_nl_policy[NSHKMOD_ATTR_MAX + 1] = {
	[NSHKMOD_ATTR_IFINDEX]	= { .type = NLA_U32, },
	[NSHKMOD_ATTR_SPI]	= { .type = NLA_U32, },
	[NSHKMOD_ATTR_SI]	= { .type = NLA_U8, },
	[NSHKMOD_ATTR_ENCAP]	= { .type = NLA_U8, },
	[NSHKMOD_ATTR_REMOTE]	= { .type = NLA_U32, },
	[NSHKMOD_ATTR_LOCAL]	= { .type = NLA_U32, },
	[NSHKMOD_ATTR_VNI]	= { .type = NLA_U32, },
};

static int
nsh_nl_cmd_path_dst_set (struct sk_buff * skb, struct genl_info * info)
{
	/* set a path->remote_ip/dev mapping */

	u8 si, encap_type;
	__u32 spi, ifindex, vni, key;
	__be32 remote_ip, local_ip;

	if (!info->attrs[NSHKMOD_ATTR_SPI] || !info->attrs[NSHKMOD_ATTR_SI]) {
		return -EINVAL;
	}
	spi = nla_get_u32 (info->attrs[NSHKMOD_ATTR_SPI]);
	si = nla_get_u8 (info->attrs[NSHKMOD_ATTR_SI]);

	ifindex = 0;
	remote_ip = 0;
	local_ip = 0;
	vni = 0;

	if (info->attrs[NSHKMOD_ATTR_IFINDEX]) {
		ifindex = nla_get_u32 (info->attrs[NSHKMOD_ATTR_IFINDEX]);
	} else {
		if (!info->attrs[NSHKMOD_ATTR_ENCAP] ||
		    !info->attrs[NSHKMOD_ATTR_REMOTE] ||
		    !info->attrs[NSHKMOD_ATTR_LOCAL])
			return -EINVAL;

		encap_type = nla_get_u8 (info->attrs[NSHKMOD_ATTR_ENCAP]);
		remote_ip = nla_get_be32 (info->attrs[NSHKMOD_ATTR_REMOTE]);
		local_ip = nla_get_be32 (info->attrs[NSHKMOD_ATTR_LOCAL]);
		if (info->attrs[NSHKMOD_ATTR_VNI]) {
			vni = nla_get_u32 (info->attrs[NSHKMOD_ATTR_VNI]);
		}
		if (encap_type != NSH_ENCAP_TYPE_VXLAN) {
			pr_debug ("version %s only support VXLAN-GPE\n",
				  NSHKMOD_VERSION);
			return -EINVAL;
		}
	}

	key = htonl ((spi << 8) | si);

	if (ifindex) {
		/* path->device mapping */
		struct net_device * dev;
		dev = __dev_get_by_index (sock_net (skb->sk), ifindex);
		if (!dev) {
			pr_debug ("device for index %u does not exist\n",
				  ifindex);
			return -EINVAL;
		}
		if (dev->netdev_ops != &nsh_netdev_ops) {
			pr_debug ("%s is not nsh interface\n", dev->name);
			return -EINVAL;
		}

		nsh_add_table (net_generic (dev_net (dev), nsh_net_id),
			       key, netdev_priv (dev), NULL);
	} else {
		/* path->remote mapping */
		struct nsh_dst * dst;

		dst = (struct nsh_dst *) kmalloc (sizeof (*dst), GFP_KERNEL);
		if (!dst) {
			pr_debug ("no memory to alloc dst entry\n");
			return -ENOMEM;
		}
		dst->encap_type = encap_type;
		dst->remote_ip = remote_ip;
		dst->local_ip = local_ip;
		dst->vni = vni;

		nsh_add_table (net_generic (sock_net (skb->sk), nsh_net_id),
			       key, NULL, dst);
	}

	return 0;
}

static int
nsh_nl_cmd_path_dst_unset (struct sk_buff * skb, struct genl_info * info)
{
	/* unset a path->remote_ip/dev mapping */

	u8 si;
	__u32 spi, key;
	struct nsh_table * nt;

	if (!info->attrs[NSHKMOD_ATTR_SPI] || !info->attrs[NSHKMOD_ATTR_SI]) {
		return -EINVAL;
	}
	spi = nla_get_u32 (info->attrs[NSHKMOD_ATTR_SPI]);
	si = nla_get_u8 (info->attrs[NSHKMOD_ATTR_SI]);

	key = htonl ((spi << 8) | si);

	nt = nsh_find_table (net_generic (sock_net (skb->sk), nsh_net_id),
			     key);
	if (!nt)
		return -ENOENT;

	nsh_delete_table (nt);

	return 0;
}

static int
nsh_nl_cmd_dev_path_set (struct sk_buff * skb, struct genl_info * info)
{
	/* set a dev->path mapping */
	u8 si;
	__u32 ifindex, spi, key;
	struct net_device * dev;
	struct nsh_dev * ndev;

	if (!info->attrs[NSHKMOD_ATTR_IFINDEX] ||
	    !info->attrs[NSHKMOD_ATTR_SPI] || !info->attrs[NSHKMOD_ATTR_SI]) {
		return -EINVAL;
	}
	ifindex = nla_get_u32 (info->attrs[NSHKMOD_ATTR_IFINDEX]);
	spi = nla_get_u32 (info->attrs[NSHKMOD_ATTR_SPI]);
	si = nla_get_u8 (info->attrs[NSHKMOD_ATTR_SI]);

	key = htonl ((spi << 8) | 8);

	dev = __dev_get_by_index (sock_net (skb->sk), ifindex);
	if (!dev) {
		pr_debug ("device for index %u does not exist\n", ifindex);
		return -EINVAL;
	}
	if (dev->netdev_ops != &nsh_netdev_ops) {
		pr_debug ("%s is not nsh interface\n", dev->name);
		return -EINVAL;
	}

	ndev = netdev_priv (dev);
	ndev->key = key;

	return 0;
}

static int
nsh_nl_cmd_dev_path_unset (struct sk_buff * skb, struct genl_info * info)
{
	/* unset a dev->path mapping */
	__u32 ifindex;
	struct net_device * dev;
	struct nsh_dev * ndev;

	if (!info->attrs[NSHKMOD_ATTR_IFINDEX])
		return -EINVAL;

	ifindex = nla_get_u32 (info->attrs[NSHKMOD_ATTR_IFINDEX]);

	dev = __dev_get_by_index (sock_net (skb->sk), ifindex);
	if (!dev) {
		pr_debug ("device for index %u does not exist\n", ifindex);
		return -EINVAL;
	}
	if (dev->netdev_ops != &nsh_netdev_ops) {
		pr_debug ("%s is not nsh interface\n", dev->name);
		return -EINVAL;
	}

	ndev = netdev_priv (dev);
	ndev->key = 0;

	return 0;
}

static int
nsh_nl_cmd_path_dump (struct sk_buff * skb, struct netlink_callback * cb)
{
	return 0;
}

static int
nsh_nl_cmd_dev_dump (struct sk_buff * skb, struct netlink_callback * cb)
{
	return 0;
}

static struct genl_ops nshkmod_nl_ops[] = {
	{
		.cmd	= NSHKMOD_CMD_PATH_DST_SET,
		.doit	= nsh_nl_cmd_path_dst_set,
		.policy	= nshkmod_nl_policy,
		//.flags	= GENL_ADMIN_PERM,
	},
	{
		.cmd	= NSHKMOD_CMD_PATH_DST_UNSET,
		.doit	= nsh_nl_cmd_path_dst_unset,
		.policy	= nshkmod_nl_policy,
		//.flags	= GENL_ADMIN_PERM,
	},
	{
		.cmd	= NSHKMOD_CMD_DEV_PATH_SET,
		.doit	= nsh_nl_cmd_dev_path_set,
		.policy	= nshkmod_nl_policy,
		//.flags	= GENL_ADMIN_PERM,
	},
	{
		.cmd	= NSHKMOD_CMD_DEV_PATH_UNSET,
		.doit	= nsh_nl_cmd_dev_path_unset,
		.policy	= nshkmod_nl_policy,
		//.flags	= GENL_ADMIN_PERM,
	},
	{
		.cmd	= NSHKMOD_CMD_PATH_DUMP,
		.dumpit	= nsh_nl_cmd_path_dump,
		.policy	= nshkmod_nl_policy,
		//.flags	= GENL_ADMIN_PERM,
	},
	{
		.cmd	= NSHKMOD_CMD_DEV_DUMP,
		.dumpit	= nsh_nl_cmd_dev_dump,
		.policy	= nshkmod_nl_policy,
		//.flags	= GENL_ADMIN_PERM,
	},
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

	rc = genl_register_family_with_ops (&nshkmod_nl_family,
					    nshkmod_nl_ops);
	if (rc != 0)
		goto genl_failed;

	printk (KERN_INFO PRNSH "nsh kmod version %s loaded\n",
		NSHKMOD_VERSION);

	return 0;

genl_failed:
	rtnl_link_unregister (&nshkmod_link_ops);
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
