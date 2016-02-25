/* nshkmod.c
 * NSH kernel module implementation.
 */

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
 * MD-type 1, four Context Header, 4-byte each.
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
MODULE_VERSION(NSHKMOD_VERSION);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ryo Nakamura <upa@haeena.net>");
MODULE_DESCRIPTION("network service header kernel module implementation");
MODULE_ALIAS_RTNL_LINK("nsh");

#define VXLAN_HLEN	(sizeof(struct vxlanhdr) + sizeof(struct udphdr))
#define NSH_MDTYPE1_HLEN	(sizeof(struct nsh_base_hdr) + \
				 sizeof(struct nsh_path_hdr) + \
				 sizeof(struct nsh_ctx_type1))
#define NSH_MDTYPE2_0_HLEN	(sizeof(struct nsh_base_hdr) + \
				 sizeof(struct nsh_path_hdr))

#define NSH_VXLAN_TTL	64

#define VXLAN_GPE_PORT	htons(4790)
#define VXLAN_GPE_FLAGS 0x0C000000	/* set next protocol */
#define VXLAN_GPE_PROTO_IPV4	0x01
#define VXLAN_GPE_PROTO_IPV6	0x02
#define VXLAN_GPE_PROTO_ETH	0x03
#define VXLAN_GPE_PROTO_NSH	0x04
#define VXLAN_GPE_PROTO_MPLS	0x05

#define ETH_P_NSH	0x894F	/* Cisco vPath Network Service Header
				 * draft-ietf-sfc-nsh-01 sec 9.3 */

#define DEFAULT_MTU	1500

static int nsh_net_id;
static u32 nshkmod_salt __read_mostly;


/* Pseudo network device */
struct nsh_dev {
	struct list_head	list;	/* nsh_net->dev_list */
	struct rcu_head		rcu;

	struct net_device	*dev;

	__be32	key;	/* SPI and SI. 0 means not assigned  */
};

/* remote node (next node of the path) infromation */
struct nsh_dst {

	/* vxlan */
	__be32	remote_ip;	/* XXX: should support IPv6 */
	__be32	local_ip;	/* XXX: should support IPv6 */
	__be32	vni;		/* vni for vxlan encap */

	/* ether */
	struct net_device *lowerdev;
	__u8	eth_addr[ETH_ALEN];	/* encap ehter */
};

/* nsh_table entry. SPI+SI -> Dst (dev or remote) */
struct nsh_table {
	struct hlist_node	hlist;	/* linked list of hashtable */
	struct rcu_head		rcu;
	struct net		*net;
	unsigned long		updated;	/* jiffies */


	__be32	key;	/* SPI and SI */
	__be32	spi;	/* service path index */
	__u8	si;	/* service index */
	__u8	mdtype;	/* MD-type */

	__u8	encap_type;

	struct nsh_dev	*rdev;
	struct nsh_dst	*rdst;

	/* XXX: nsh_net->nsh_table[n] should be locked when add or delete */
};

/* per net_namespace structure */
struct nsh_net {
	struct net	*net;

#define NSH_HASH_BITS	8
#define NSH_HASH_SIZE	(1 << NSH_HASH_BITS)
	struct hlist_head	nsh_table[NSH_HASH_SIZE]; /* nsh_table hash */
	struct list_head	dev_list;	/* nsh_dev list*/
	struct socket		*sock;		/* udp tunnel socket */
};


static inline struct hlist_head *nsh_table_head(struct nsh_net *nnet,
						 __be32 key) {
	return &nnet->nsh_table[hash_32(key, NSH_HASH_BITS)];
}

static struct nsh_table *nsh_find_table(struct nsh_net *nnet, __be32 key)
{
	struct hlist_head *head = nsh_table_head(nnet, key);
	struct nsh_table *nt;

	hlist_for_each_entry_rcu(nt, head, hlist) {
		if (key == nt->key)
			return nt;
	}

	return NULL;
}

static int nsh_add_table(struct nsh_net *nnet, __be32 key, __u8 mdtype,
			 __u8 encap_type, struct nsh_dev *rdev,
			 struct nsh_dst *rdst)
{
	struct nsh_table *nt;

	nt = kmalloc(sizeof(*nt), GFP_KERNEL);
	if (!nt)
		return -ENOMEM;

	memset(nt, 0, sizeof(*nt));

	nt->net	= nnet->net;
	nt->key = key;
	nt->spi = ntohl(key) >> 8;
	nt->si	= ntohl(key) & 0x000000FF;
	nt->mdtype = mdtype;
	nt->encap_type = encap_type;
	nt->rdev = rdev;
	nt->rdst = rdst;	/* which one (rdev or rdst) must be NULL */

	hlist_add_head_rcu(&nt->hlist, nsh_table_head(nnet, key));

	return 0;
}

static void nsh_free_table(struct rcu_head *head)
{
	struct nsh_table *nt = container_of(head, struct nsh_table, rcu);

	kfree(nt->rdst);
	kfree(nt);
}

static void nsh_delete_table(struct nsh_table *nt)
{
	hlist_del_rcu(&nt->hlist);
	call_rcu(&nt->rcu, nsh_free_table);
}

static void nsh_destroy_table(struct nsh_net *nnet)
{
	unsigned int n;

	for (n = 0; n < NSH_HASH_SIZE; n++) {
		struct hlist_node *ptr, *tmp;

		hlist_for_each_safe(ptr, tmp, &nnet->nsh_table[n]) {
			struct nsh_table *nt;

			nt = container_of(ptr, struct nsh_table, hlist);
			nsh_delete_table(nt);
		}
	}
}

static int nsh_recv(struct net *net, struct sk_buff *skb)
{
	int hdrlen;
	struct nsh_base_hdr *nbh;
	struct nsh_path_hdr *nph;
	struct nsh_table *nt;
	struct nsh_net *nnet = net_generic(net, nsh_net_id);
	struct pcpu_sw_netstats *stats;

	nbh = (struct nsh_base_hdr *)skb->data;
	nph = (struct nsh_path_hdr *)(nbh + 1);

	if (unlikely(!NSH_BASE_CHECK_VERSION(nbh->flags, 0))) {
		pr_debug("invalid nsh version flag %#x\n", nbh->flags);
		return -1;
	}
	if (NSH_BASE_OAM(nbh->flags)) {
		pr_debug("oam is not supported %#x\n", nbh->flags);
		return -1;
	}
	/* XXX: C bit should be considered on software? */

	if (nbh->protocol != NSH_BASE_PROTO_ETH) {
		pr_debug("only supports ethrenet. protocol is %u.\n",
			 nbh->protocol);
		return -1;
	}

	if ((ntohl(nph->spisi) & 0x000000FF) == 0) {
		/* service index 0 packet is dropped (draft 4.3) */
		return -1;
	}

	nt = nsh_find_table(nnet, nph->spisi);
	if (!nt || !nt->rdev)
		return -1;

	hdrlen = NSH_BASE_LENGTH(nbh->length) << 2;
	__skb_pull(skb, hdrlen);
	skb_reset_mac_header(skb);
	skb->protocol = eth_type_trans(skb, nt->rdev->dev);
	skb->encapsulation = 0;
	skb_scrub_packet(skb, !net_eq(net, dev_net(nt->rdev->dev)));
	skb_reset_network_header(skb);

	stats = this_cpu_ptr(nt->rdev->dev->tstats);
	u64_stats_update_begin(&stats->syncp);
	stats->rx_packets++;
	stats->rx_bytes += skb->len;
	u64_stats_update_end(&stats->syncp);

	netif_rx(skb);

	return 0;
}

static int nsh_vxlan_udp_encap_recv(struct sock *sk, struct sk_buff *skb)
{
	/* pop udp and vxlan header. checking spi si and forwarding to
	 * appropriate interface are done by nsh_recv (outer
	 * encapsulation protocol independent). */

	struct vxlanhdr *vxh;

	if (!pskb_may_pull(skb, VXLAN_HLEN))
		goto err;

	vxh = (struct vxlanhdr *)(udp_hdr(skb) + 1);
	if (vxh->vx_flags != htonl(VXLAN_GPE_FLAGS | VXLAN_GPE_PROTO_NSH)) {
		netdev_dbg(skb->dev, "invalid vxlan flags %#x\n",
			   ntohl(vxh->vx_flags));
		goto err;
	}

	__skb_pull(skb, VXLAN_HLEN);

	return nsh_recv(sock_net(sk), skb);

err:
	return 1;
}

static int nsh_ether_encap_recv(struct sk_buff *skb, struct net_device *dev,
				struct packet_type *pt,
				struct net_device *orig_dev)
{
	int err;

	if (skb->pkt_type == PACKET_OTHERHOST)
		goto drop;

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (skb == NULL) {
		IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INDISCARDS);
		goto out;
	}

	/* XXX: ???
	if (!pskb_may_pull (skb, ETH_HLEN))
		goto inhdr_error;

	__skb_pull (skb, ETH_HLEN);
	*/

	err = nsh_recv(dev_net(dev), skb);
	if (err < 0)
		goto out;

	return 1;
/*
inhdr_error:
	IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INHDRERRORS);
*/
drop:
	kfree_skb(skb);
out:
	return NET_RX_DROP;
}

static int nsh_xmit_vxlan_skb(struct socket *sock, struct net * net,
			      struct rtable *rt, struct sk_buff *skb,
			      __be32 src, __be32 dst, __be16 src_port,
			      __be16 dst_port, __be32 vni)
{
	int err;
	struct vxlanhdr *vxh;
	bool udp_sum = !sock->sk->sk_no_check_tx;

	skb = udp_tunnel_handle_offloads(skb, udp_sum);

	err = skb_cow_head(skb, VXLAN_HEADROOM);
	if (unlikely(err)) {
		kfree_skb(skb);
		return -ENOMEM;
	}

	vxh = (struct vxlanhdr *)__skb_push(skb, sizeof(*vxh));
	vxh->vx_flags = htonl(VXLAN_GPE_FLAGS | VXLAN_GPE_PROTO_NSH);
	vxh->vx_vni = htonl(vni << 8);

	return udp_tunnel_xmit_skb(sock, rt, skb, src, dst, 0, NSH_VXLAN_TTL,
				   0, src_port, dst_port, net);
}

static int nsh_xmit_vxlan(struct sk_buff *skb, struct nsh_net *nnet,
			  struct nsh_dev *ndev, struct nsh_table *nt,
			  __be16 src_port)
{
	struct flowi4 fl4;
	struct rtable *rt;

	memset(&fl4, 0, sizeof(fl4));
	fl4.daddr = nt->rdst->remote_ip;
	fl4.saddr = nt->rdst->local_ip;

	rt = ip_route_output_key(dev_net(ndev->dev), &fl4);
	if (IS_ERR(rt)) {
		netdev_dbg(ndev->dev, "no route found to %pI4\n",
			   (struct in_addr *)&nt->rdst->remote_ip);
		ndev->dev->stats.tx_carrier_errors++;
		ndev->dev->stats.tx_dropped++;
		return -ENOENT;
	}

	return nsh_xmit_vxlan_skb(nnet->sock, nnet->net, rt,
				  skb, fl4.saddr, nt->rdst->remote_ip,
				  src_port, VXLAN_GPE_PORT, nt->rdst->vni);
}

static int nsh_xmit_ether(struct sk_buff *skb, struct nsh_net *nnet,
			  struct nsh_dev *ndev, struct nsh_table *nt)
{
	int err;
	struct ethhdr *eth;
	struct nsh_dst *dst;

	err = skb_cow_head(skb, ETH_HLEN);
	if (unlikely(err)) {
		kfree_skb(skb);
		return -ENOMEM;
	}

	if (!nt->rdst || !nt->rdst->lowerdev) {
		pr_debug("%s: invalid link\n", __func__);
		return -ENODEV;
	}
	dst = nt->rdst;

	eth = (struct ethhdr *)__skb_push(skb, sizeof(*eth));
	ether_addr_copy(eth->h_dest, dst->eth_addr);
	ether_addr_copy(eth->h_source, dst->lowerdev->dev_addr);
	eth->h_proto = htons(ETH_P_NSH);

	skb->protocol = eth->h_proto;
	skb->dev = nt->rdst->lowerdev;
	skb_reset_mac_header(skb);

	return dev_queue_xmit(skb);
}

static netdev_tx_t nsh_xmit(struct sk_buff *skb, struct net_device *dev)
{
	int rc;
	unsigned int len, nhlen;
	__be16 src_port = VXLAN_GPE_PORT;
	struct pcpu_sw_netstats *tx_stats;
	struct nsh_dev *ndev = netdev_priv(dev);
	struct nsh_net *nnet = net_generic(dev_net(dev), nsh_net_id);
	struct nsh_table *nt;
	struct nsh_base_hdr *nbh;
	struct nsh_path_hdr *nph;
	struct nsh_ctx_type1 *ctx;

	nt = nsh_find_table(nnet, ndev->key);
	if (!nt) {
		if (net_ratelimit())
			netdev_dbg(dev, "path is not assigned\n");
		goto tx_err;
	}

	len = skb->len;

	switch (nt->mdtype) {
	case NSH_BASE_MDTYPE1:
		nhlen = NSH_MDTYPE1_HLEN;
		break;
	case NSH_BASE_MDTYPE2:
		nhlen = NSH_MDTYPE2_0_HLEN;
		break;
	default:
		pr_debug("invalid MD-type %u\n", nt->mdtype);
		goto tx_err;
	}

	if (nt->encap_type == NSH_ENCAP_TYPE_VXLAN) {
		/* get udp src port for ether hash before encapsulation.
		 * XXX: src_port_max and _min should be implemented.
		 * 0, 0, means default src port range. */
		src_port = udp_flow_src_port(dev_net(dev), skb, 0, 0, true);
	}

	rc = skb_cow_head(skb, nhlen);
	if (unlikely(rc)) {
		netdev_dbg(dev, "failed to skb_cow_head\n");
		kfree_skb(skb);
		goto tx_err;
	}

	if (nt->mdtype == NSH_BASE_MDTYPE1) {
		ctx = (struct nsh_ctx_type1 *)__skb_push(skb, sizeof(*ctx));
		/* XXX: no metadata. how to implement other drafts? */
		ctx->ctx[0] = 0;
		ctx->ctx[1] = 0;
		ctx->ctx[2] = 0;
		ctx->ctx[3] = 0;
	}

	nph = (struct nsh_path_hdr *)__skb_push(skb, sizeof(*nph));
	nph->spisi = ndev->key;

	nbh = (struct nsh_base_hdr *)__skb_push(skb, sizeof(*nbh));
	nbh->flags	= 0;
	nbh->length	= nhlen >> 2;	/* 4byte word */
	nbh->mdtype	= nt->mdtype;
	nbh->protocol	= NSH_BASE_PROTO_ETH;

	if (nt->rdev) {
		/* nexthop is nsh interface in this machine. */
		nsh_recv(dev_net(dev), skb);
		goto update_stats;
	}

	if (nt->rdst) {
		switch (nt->encap_type) {
		case NSH_ENCAP_TYPE_VXLAN:
			rc = nsh_xmit_vxlan(skb, nnet, ndev, nt, src_port);
			if (rc < 0)
				goto tx_err;
			break;
		case NSH_ENCAP_TYPE_ETHER:
			rc = nsh_xmit_ether(skb, nnet, ndev, nt);
			if (rc < 0)
				goto tx_err;
			break;
		default:
			netdev_dbg(dev, "invalid encap type %d\n",
				   nt->encap_type);
			goto tx_err;
		}
	}

update_stats:
	tx_stats = this_cpu_ptr(dev->tstats);
	u64_stats_update_begin(&tx_stats->syncp);
	tx_stats->tx_packets++;
	tx_stats->tx_bytes += len;
	u64_stats_update_end(&tx_stats->syncp);

	return NETDEV_TX_OK;

tx_err:
	dev->stats.tx_errors++;

	return NETDEV_TX_OK;
}

/* setup stats when device is created */
static int nsh_init(struct net_device *dev)
{
	dev->tstats = netdev_alloc_pcpu_stats(struct pcpu_sw_netstats);
	if (!dev->tstats)
		return -ENOMEM;

	return 0;
}

static void nsh_uninit(struct net_device *dev)
{
	free_percpu(dev->tstats);
}

static int nsh_open(struct net_device *dev)
{
	return 0;
}

static int nsh_stop(struct net_device *dev)
{
	return 0;
}

static const struct net_device_ops nsh_netdev_ops = {
	.ndo_init		= nsh_init,
	.ndo_uninit		= nsh_uninit,
	.ndo_open		= nsh_open,
	.ndo_stop		= nsh_stop,
	.ndo_start_xmit		= nsh_xmit,
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
static void nsh_setup(struct net_device *dev)
{
	struct nsh_dev *ndev = netdev_priv(dev);

	eth_hw_addr_random(dev);
	ether_setup(dev);
	dev->needed_headroom = ETH_HLEN + VXLAN_HEADROOM + NSH_MDTYPE1_HLEN;

	dev->netdev_ops = &nsh_netdev_ops;
	dev->destructor = free_netdev;
	SET_NETDEV_DEVTYPE(dev, &nsh_type);

	dev->tx_queue_len = 0;
	dev->features	|= NETIF_F_LLTX;
	dev->features	|= NETIF_F_NETNS_LOCAL;
	netif_keep_dst(dev);
	dev->priv_flags |= IFF_LIVE_ADDR_CHANGE;

	INIT_LIST_HEAD(&ndev->list);

	ndev->dev = dev;
	ndev->key = 0;
}

static int nsh_newlink(struct net *net, struct net_device *dev,
		       struct nlattr *tb[], struct nlattr *data[])
{
	int err;
	__u32 spi;
	__u8 si;
	struct nsh_net *nnet = net_generic(net, nsh_net_id);
	struct nsh_dev *ndev = netdev_priv(dev);

	if (data && data[IFLA_NSHKMOD_SPI] && data[IFLA_NSHKMOD_SI]) {
		spi = nla_get_u32(data[IFLA_NSHKMOD_SPI]);
		si = nla_get_u8(data[IFLA_NSHKMOD_SI]);
		ndev->key = htonl((spi << 8) | si);
	}

	err = register_netdevice(dev);
	if (err) {
		netdev_err(dev, "failed to register netdevice\n");
		return err;
	}

	list_add_tail_rcu(&ndev->list, &nnet->dev_list);

	return 0;
}

static void nsh_dellink(struct net_device *dev, struct list_head *head)
{
	unsigned int n;
	struct nsh_dev *ndev = netdev_priv(dev);
	struct nsh_net *nnet = net_generic(dev_net(dev), nsh_net_id);

	/* remove this device from nsh table */
	for (n = 0; n < NSH_HASH_SIZE; n++) {
		struct nsh_table *nt;
		struct hlist_node *ptr, *tmp;

		hlist_for_each_safe(ptr, tmp, &nnet->nsh_table[n]) {
			nt = container_of(ptr, struct nsh_table, hlist);
			if (nt->rdev == ndev)
				nsh_delete_table(nt);
		}
	}

	list_del_rcu(&ndev->list);

	unregister_netdevice_queue(dev, head);
}

static size_t nsh_get_size(const struct net_device *dev)
{
	return nla_total_size(sizeof(__u32)) +	/* IFLA_NSHKMOD_SPI */
		nla_total_size(sizeof(__u8)) +	/* IFLA_NSHKMOD_SI */
		0;
}

static int nsh_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
	__u8 si;
	__u32 spi;

	const struct nsh_dev *ndev = netdev_priv(dev);

	spi = ntohl(ndev->key) >> 8;
	si = ntohl(ndev->key) & 0x00000FF;

	if (nla_put_u32(skb, IFLA_NSHKMOD_SPI, spi) ||
	    nla_put_u8(skb, IFLA_NSHKMOD_SI, si))
		return -EMSGSIZE;

	return 0;
}

static struct rtnl_link_ops nshkmod_link_ops __read_mostly = {
	.kind		= "nsh",
	.maxtype	= IFLA_NSHKMOD_MAX,
	.priv_size	= sizeof(struct nsh_dev),
	.setup		= nsh_setup,
	.newlink	= nsh_newlink,
	.dellink	= nsh_dellink,
	.get_size	= nsh_get_size,
	.fill_info	= nsh_fill_info,
};

static struct packet_type nshkmod_packet_type __read_mostly = {
	.type = cpu_to_be16 (ETH_P_NSH),
	.func = nsh_ether_encap_recv,
};

static void nsh_handle_lowerdev_unregister(struct nsh_net *nnet,
					   struct net_device *dev)
{
	/* check ENCAP_TYPE_ETHER rdst */

	unsigned int n;

	for (n = 0; n < NSH_HASH_SIZE; n++) {
		struct hlist_node *ptr, *tmp;

		hlist_for_each_safe(ptr, tmp, &nnet->nsh_table[n]) {
			struct nsh_table *nt;

			nt = container_of(ptr, struct nsh_table, hlist);
			if (nt->rdst && nt->rdst->lowerdev == dev)
				nsh_delete_table(nt);
		}
	}
}

static int nsh_lowerdev_event(struct notifier_block *unused,
			      unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct nsh_net *nnet = net_generic(dev_net(dev), nsh_net_id);

	if (event == NETDEV_UNREGISTER)
		nsh_handle_lowerdev_unregister(nnet, dev);

	return NOTIFY_DONE;
}

static struct notifier_block nshkmod_notifier_block __read_mostly = {
	.notifier_call = nsh_lowerdev_event,
};

static struct socket *nsh_vxlan_create_sock(struct net *net, __be16 port)
{
	/* XXX: vxlan_skb_xmit does not have API to configure flags in
	 * vxlan header (kernel 3.19) that is needed for VXLAN-GPE.
	 * So, normal udp socket and udp_tunnel_xmit are used. */

	int err;
	struct socket *sock;
	struct udp_port_cfg udp_conf;
	struct udp_tunnel_sock_cfg tunnel_cfg;

	memset(&udp_conf, 0, sizeof(udp_conf));

	/* XXX: should support IPv6 */
	udp_conf.family = AF_INET;
	udp_conf.local_ip.s_addr = INADDR_ANY;
	udp_conf.local_udp_port = port;

	err = udp_sock_create(net, &udp_conf, &sock);
	if (err < 0)
		return ERR_PTR(err);

	tunnel_cfg.encap_type = 1;
	tunnel_cfg.encap_rcv = nsh_vxlan_udp_encap_recv;
	tunnel_cfg.encap_destroy = NULL;
	setup_udp_tunnel_sock(net, sock, &tunnel_cfg);

	return sock;
}

static __net_init int nshkmod_init_net(struct net *net)
{
	unsigned int n;
	struct nsh_net *nnet = net_generic(net, nsh_net_id);

	for (n = 0; n < NSH_HASH_SIZE; n++)
		INIT_HLIST_HEAD(&nnet->nsh_table[n]);

	INIT_LIST_HEAD(&nnet->dev_list);
	nnet->net = net;

	nnet->sock = nsh_vxlan_create_sock(net, VXLAN_GPE_PORT);
	if (IS_ERR(nnet->sock)) {
		pr_err("nshkmod: failed to add vxlan udp socket\n");
		return -EINVAL;
	}

	return 0;
}

static void __net_exit nshkmod_exit_net(struct net *net)
{
	struct nsh_net *nnet = net_generic(net, nsh_net_id);
	struct nsh_dev *ndev, *next;
	struct net_device *dev, *aux;

	LIST_HEAD(list);

	rtnl_lock();
	for_each_netdev_safe(net, dev, aux)
		if (dev->rtnl_link_ops == &nshkmod_link_ops)
			unregister_netdevice_queue(dev, &list);

	list_for_each_entry_safe(ndev, next, &nnet->dev_list, list) {
		if (!net_eq(dev_net(ndev->dev), net))
			unregister_netdevice_queue(ndev->dev, &list);
	}
	unregister_netdevice_many(&list);
	rtnl_unlock();

	nsh_destroy_table(nnet);

	udp_tunnel_sock_release(nnet->sock);
}

static struct pernet_operations nshkmod_net_ops = {
	.init	= nshkmod_init_net,
	.exit	= nshkmod_exit_net,
	.id	= &nsh_net_id,
	.size	= sizeof(struct nsh_net),
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
	[NSHKMOD_ATTR_ETHADDR]	= { .type = NLA_BINARY,
				    .len = ETH_ALEN },
};

static int nsh_nl_cmd_path_dst_set(struct sk_buff *skb,
				   struct genl_info *info)
{
	/* set a path->remote or device mapping */

	u8 si, encap_type, mdtype, eth_addr[ETH_ALEN];
	__u32 spi, ifindex, vni, key;
	__be32 remote, local;
	struct net *net = sock_net(skb->sk);
	struct nsh_net *nnet = net_generic(net, nsh_net_id);
	struct nsh_table *nt;
	struct nsh_dst *dst;
	struct net_device *dev, *lowerdev;

	if (!info->attrs[NSHKMOD_ATTR_SPI] || !info->attrs[NSHKMOD_ATTR_SI])
		return -EINVAL;

	spi = nla_get_u32(info->attrs[NSHKMOD_ATTR_SPI]);
	si = nla_get_u8(info->attrs[NSHKMOD_ATTR_SI]);

	key = htonl((spi << 8) | si);
	nt = nsh_find_table(nnet, key);
	if (nt)
		return -EEXIST;

	mdtype = (info->attrs[NSHKMOD_ATTR_MDTYPE]) ?
		nla_get_u8(info->attrs[NSHKMOD_ATTR_MDTYPE]) :
		NSH_BASE_MDTYPE1;
	encap_type = 0;
	ifindex = 0;
	remote = 0;
	local = 0;
	vni = 0;
	memset(eth_addr, 0, ETH_ALEN);

	if (!info->attrs[NSHKMOD_ATTR_ENCAP])
		encap_type = NSH_ENCAP_TYPE_NONE;
	else
		encap_type = nla_get_u8(info->attrs[NSHKMOD_ATTR_ENCAP]);

	switch (encap_type) {
	case NSH_ENCAP_TYPE_NONE: /* inner device */
		if (!info->attrs[NSHKMOD_ATTR_IFINDEX])
			return -EINVAL;
		ifindex = nla_get_u32(info->attrs[NSHKMOD_ATTR_IFINDEX]);

		dev = __dev_get_by_index(net, ifindex);
		if (!dev) {
			pr_debug("device for index %u does not exist\n",
				 ifindex);
			return -ENODEV;
		}
		if (dev->netdev_ops != &nsh_netdev_ops) {
			pr_debug("%s is not nsh interface\n", dev->name);
			return -EINVAL;
		}

		nsh_add_table(nnet, key, mdtype, encap_type,
			      netdev_priv(dev), NULL);
		break;

	case NSH_ENCAP_TYPE_VXLAN:
		if (!info->attrs[NSHKMOD_ATTR_ENCAP] ||
		    !info->attrs[NSHKMOD_ATTR_REMOTE])
			return -EINVAL;
		remote = nla_get_be32(info->attrs[NSHKMOD_ATTR_REMOTE]);

		if (info->attrs[NSHKMOD_ATTR_LOCAL])
			local = nla_get_be32(info->attrs[NSHKMOD_ATTR_LOCAL]);

		if (info->attrs[NSHKMOD_ATTR_VNI])
			vni = nla_get_u32(info->attrs[NSHKMOD_ATTR_VNI]);

		dst = kmalloc(sizeof(*dst), GFP_KERNEL);
		if (!dst)
			return -ENOMEM;

		dst->remote_ip = remote;
		dst->local_ip = local;
		dst->vni = vni;

		nsh_add_table(nnet, key, mdtype, encap_type, NULL, dst);
		break;

	case NSH_ENCAP_TYPE_ETHER:
		if (!info->attrs[NSHKMOD_ATTR_IFINDEX] ||
		    !info->attrs[NSHKMOD_ATTR_ETHADDR])
			return -EINVAL;
		ifindex = nla_get_u32(info->attrs[NSHKMOD_ATTR_IFINDEX]);
		nla_memcpy(eth_addr, info->attrs[NSHKMOD_ATTR_ETHADDR],
			   ETH_ALEN);

		lowerdev = __dev_get_by_index(net, ifindex);
		if (!lowerdev) {
			pr_debug("ifindex %d does not exist\n", ifindex);
			return -ENODEV;
		}
		if (lowerdev->netdev_ops == &nsh_netdev_ops) {
			pr_debug("nsh device can't become link of a path\n");
			return -EINVAL;
		}

		dst = kmalloc(sizeof(*dst), GFP_KERNEL);
		if (!dst)
			return -ENOMEM;

		dst->lowerdev = lowerdev;
		ether_addr_copy(dst->eth_addr, eth_addr);

		nsh_add_table(nnet, key, mdtype, encap_type, NULL, dst);
		break;

	default:
		/* unsupported encapsulation type */
		return -EINVAL;
	}

	return 0;
}

static int nsh_nl_cmd_path_dst_unset(struct sk_buff *skb,
				     struct genl_info *info)
{
	/* unset a path->remote_ip/dev mapping */

	u8 si;
	__u32 spi, key;
	struct nsh_table *nt;

	if (!info->attrs[NSHKMOD_ATTR_SPI] || !info->attrs[NSHKMOD_ATTR_SI])
		return -EINVAL;

	spi = nla_get_u32(info->attrs[NSHKMOD_ATTR_SPI]);
	si = nla_get_u8(info->attrs[NSHKMOD_ATTR_SI]);

	key = htonl((spi << 8) | si);

	nt = nsh_find_table(net_generic(sock_net(skb->sk), nsh_net_id), key);
	if (!nt)
		return -ENOENT;

	nsh_delete_table(nt);

	return 0;
}

void nsh_change_mtu_for_path(struct net_device *dev, struct nsh_table *nt)
{
	int hlen;

	hlen = (nt->mdtype == NSH_BASE_MDTYPE1) ?
		NSH_MDTYPE1_HLEN : NSH_MDTYPE2_0_HLEN;

	switch (nt->encap_type) {
	case NSH_ENCAP_TYPE_VXLAN:
		hlen += VXLAN_HEADROOM;
		eth_change_mtu(dev, DEFAULT_MTU - hlen);
		break;

	case NSH_ENCAP_TYPE_ETHER:
		hlen += ETH_HLEN;
		eth_change_mtu(dev, nt->rdst->lowerdev->mtu - hlen);
		break;
	}
}

static int nsh_nl_cmd_dev_path_set(struct sk_buff *skb,
				   struct genl_info *info)
{
	/* set a dev->path mapping */
	u8 si;
	__u32 ifindex, spi, key;
	struct net_device *dev;
	struct nsh_dev *ndev;
	struct nsh_table *nt;

	if (!info->attrs[NSHKMOD_ATTR_IFINDEX] ||
	    !info->attrs[NSHKMOD_ATTR_SPI] || !info->attrs[NSHKMOD_ATTR_SI]) {
		pr_debug("ifindex %p, spi %p, si %p\n",
			 info->attrs[NSHKMOD_ATTR_IFINDEX],
			 info->attrs[NSHKMOD_ATTR_SPI],
			 info->attrs[NSHKMOD_ATTR_SI]);
		return -EINVAL;
	}
	ifindex = nla_get_u32(info->attrs[NSHKMOD_ATTR_IFINDEX]);
	spi = nla_get_u32(info->attrs[NSHKMOD_ATTR_SPI]);
	si = nla_get_u8(info->attrs[NSHKMOD_ATTR_SI]);

	key = htonl((spi << 8) | si);

	dev = __dev_get_by_index(sock_net(skb->sk), ifindex);
	if (!dev) {
		pr_debug("device for index %u does not exist\n", ifindex);
		return -ENODEV;
	}
	if (dev->netdev_ops != &nsh_netdev_ops) {
		pr_debug("%s is not nsh interface\n", dev->name);
		return -EINVAL;
	}

	nt = nsh_find_table(net_generic(dev_net(dev), nsh_net_id), key);
	if (nt)
		nsh_change_mtu_for_path(dev, nt);

	ndev = netdev_priv(dev);
	ndev->key = key;

	return 0;
}

static int nsh_nl_cmd_dev_path_unset(struct sk_buff *skb,
				     struct genl_info *info)
{
	/* unset a dev->path mapping */
	__u32 ifindex;
	struct net_device *dev;
	struct nsh_dev *ndev;

	if (!info->attrs[NSHKMOD_ATTR_IFINDEX])
		return -EINVAL;

	ifindex = nla_get_u32(info->attrs[NSHKMOD_ATTR_IFINDEX]);

	dev = __dev_get_by_index(sock_net(skb->sk), ifindex);
	if (!dev) {
		pr_debug("device for index %u does not exist\n", ifindex);
		return -ENODEV;
	}
	if (dev->netdev_ops != &nsh_netdev_ops) {
		pr_debug("%s is not nsh interface\n", dev->name);
		return -EINVAL;
	}

	ndev = netdev_priv(dev);
	ndev->key = 0;

	return 0;
}

static int nsh_nl_table_send(struct sk_buff *skb, u32 portid, u32 seq,
			     int flags, struct nsh_table *nt)
{
	void *hdr;
	__u8 si;
	__u32 spi;
	struct nsh_dst *dst;

	hdr = genlmsg_put(skb, portid, seq, &nshkmod_nl_family, flags,
			  NSHKMOD_CMD_PATH_DUMP);
	if (!hdr)
		return -EMSGSIZE;

	spi = ntohl(nt->key) >> 8;
	si = ntohl(nt->key) & 0x000000FF;

	if (nla_put_u32(skb, NSHKMOD_ATTR_SPI, spi) ||
	    nla_put_u8(skb, NSHKMOD_ATTR_SI, si) ||
	    nla_put_u8(skb, NSHKMOD_ATTR_MDTYPE, nt->mdtype) ||
	    nla_put_u8(skb, NSHKMOD_ATTR_ENCAP, nt->encap_type))
		goto nla_put_failure;

	switch (nt->encap_type) {
	case NSH_ENCAP_TYPE_NONE:
		if (nla_put_u32(skb, NSHKMOD_ATTR_IFINDEX,
				nt->rdev->dev->ifindex))
			goto nla_put_failure;
		break;

	case NSH_ENCAP_TYPE_VXLAN:
		dst = nt->rdst;
		if (nla_put_be32(skb, NSHKMOD_ATTR_REMOTE, dst->remote_ip) ||
		    nla_put_u32(skb, NSHKMOD_ATTR_VNI, dst->vni))
			goto nla_put_failure;

		if (nt->rdst->local_ip) {
			if (nla_put_be32(skb, NSHKMOD_ATTR_LOCAL,
					  dst->local_ip))
				goto nla_put_failure;
		}

		break;

	case NSH_ENCAP_TYPE_ETHER:
		if (nla_put_u32(skb, NSHKMOD_ATTR_IFINDEX,
				nt->rdst->lowerdev->ifindex) ||
		    nla_put(skb, NSHKMOD_ATTR_ETHADDR, ETH_ALEN,
			    nt->rdst->eth_addr))
			goto nla_put_failure;
		break;
	}

	return genlmsg_end(skb, hdr);

nla_put_failure:
	genlmsg_cancel(skb, hdr);
	return -1;
}

static int nsh_nl_cmd_path_dump(struct sk_buff *skb,
				struct netlink_callback *cb)
{
	/* dump nnet->nsh_table */

	int err, idx, cnt;
	unsigned int n;
	struct nsh_net *nnet;
	struct nsh_table *nt;

	idx = cb->args[0];	/* number of next nsh_table */
	nnet = net_generic(sock_net(skb->sk), nsh_net_id);

	for (n = 0, cnt = 0; n < NSH_HASH_SIZE; n++) {
		hlist_for_each_entry_rcu(nt, &nnet->nsh_table[n], hlist) {
			if (idx > cnt) {
				cnt++;
				continue;
			}

			err = nsh_nl_table_send(skb,
						NETLINK_CB(cb->skb).portid,
						cb->nlh->nlmsg_seq,
						NLM_F_MULTI, nt);
			if (err < 0)
				return -1;

			goto out;
		}
	}

out:
	cb->args[0] = cnt + 1;

	return skb->len;
}

static int nsh_nl_dev_send(struct sk_buff *skb, u32 portid, u32 seq,
			   int flags, struct nsh_dev *ndev)
{
	void *hdr;
	__u8 si;
	__u32 spi;

	hdr = genlmsg_put(skb, portid, seq, &nshkmod_nl_family, flags,
			  NSHKMOD_CMD_DEV_DUMP);
	if (!hdr)
		return -EMSGSIZE;

	spi = ntohl(ndev->key) >> 8;
	si = ntohl(ndev->key) & 0x000000FF;

	if (nla_put_u32(skb, NSHKMOD_ATTR_SPI, spi) ||
	    nla_put_u8(skb, NSHKMOD_ATTR_SI, si) ||
	    nla_put_u32(skb, NSHKMOD_ATTR_IFINDEX, ndev->dev->ifindex))
		goto nla_put_failure;

	return genlmsg_end(skb, hdr);

nla_put_failure:
	genlmsg_cancel(skb, hdr);
	return -1;
}
static int nsh_nl_cmd_dev_dump(struct sk_buff *skb,
			       struct netlink_callback *cb)
{
	/* dump devices and their spi+si mappings */

	int err, idx, cnt;
	struct nsh_net *nnet;
	struct nsh_dev *ndev;

	cnt = 0;
	idx = cb->args[0];	/* number of next nsh_table */
	nnet = net_generic(sock_net(skb->sk), nsh_net_id);

	list_for_each_entry_rcu(ndev, &nnet->dev_list, list) {
		if (idx > cnt) {
			cnt++;
			continue;
		}

		err = nsh_nl_dev_send(skb, NETLINK_CB(cb->skb).portid,
				      cb->nlh->nlmsg_seq, NLM_F_MULTI, ndev);
		if (err < 0)
			return -1;

		break;
	}

	cb->args[0] = cnt + 1;

	return skb->len;
}

static struct genl_ops nshkmod_nl_ops[] = {
	{
		.cmd	= NSHKMOD_CMD_PATH_DST_SET,
		.doit	= nsh_nl_cmd_path_dst_set,
		.policy	= nshkmod_nl_policy,
#ifndef DEBUG
		.flags	= GENL_ADMIN_PERM,
#endif
	},
	{
		.cmd	= NSHKMOD_CMD_PATH_DST_UNSET,
		.doit	= nsh_nl_cmd_path_dst_unset,
		.policy	= nshkmod_nl_policy,
#ifndef DEBUG
		.flags	= GENL_ADMIN_PERM,
#endif
	},
	{
		.cmd	= NSHKMOD_CMD_DEV_PATH_SET,
		.doit	= nsh_nl_cmd_dev_path_set,
		.policy	= nshkmod_nl_policy,
#ifndef DEBUG
		.flags	= GENL_ADMIN_PERM,
#endif
	},
	{
		.cmd	= NSHKMOD_CMD_DEV_PATH_UNSET,
		.doit	= nsh_nl_cmd_dev_path_unset,
		.policy	= nshkmod_nl_policy,
#ifndef DEBUG
		.flags	= GENL_ADMIN_PERM,
#endif
	},
	{
		.cmd	= NSHKMOD_CMD_PATH_DUMP,
		.dumpit	= nsh_nl_cmd_path_dump,
		.policy	= nshkmod_nl_policy,
	},
	{
		.cmd	= NSHKMOD_CMD_DEV_DUMP,
		.dumpit	= nsh_nl_cmd_dev_dump,
		.policy	= nshkmod_nl_policy,
	},
};

static int __init nshkmod_init_module(void)
{
	int rc;

	get_random_bytes(&nshkmod_salt, sizeof(nshkmod_salt));

	rc = register_pernet_subsys(&nshkmod_net_ops);
	if (rc)
		goto netns_failed;

	rc = register_netdevice_notifier(&nshkmod_notifier_block);
	if (rc)
		goto notify_failed;

	rc = rtnl_link_register(&nshkmod_link_ops);
	if (rc)
		goto rtnl_failed;

	rc = genl_register_family_with_ops(&nshkmod_nl_family,
					   nshkmod_nl_ops);
	if (rc != 0)
		goto genl_failed;

	dev_add_pack(&nshkmod_packet_type);

	pr_info("nshkmod version %s loaded\n", NSHKMOD_VERSION);

	return 0;

genl_failed:
	rtnl_link_unregister(&nshkmod_link_ops);
rtnl_failed:
	unregister_netdevice_notifier(&nshkmod_notifier_block);
notify_failed:
	unregister_pernet_subsys(&nshkmod_net_ops);
netns_failed:
	return rc;
}
module_init(nshkmod_init_module);

static void __exit nshkmod_exit_module(void)
{
	rtnl_link_unregister(&nshkmod_link_ops);
	unregister_netdevice_notifier(&nshkmod_notifier_block);
	unregister_pernet_subsys(&nshkmod_net_ops);
	genl_unregister_family(&nshkmod_nl_family);
	dev_remove_pack(&nshkmod_packet_type);

	pr_info("nshkmod version %s unloaded\n", NSHKMOD_VERSION);
}
module_exit(nshkmod_exit_module);
