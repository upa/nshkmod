/* ipnsh.c */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>

#include <linux/genetlink.h>
#include "utils.h"
#include "ip_common.h"
#include "rt_names.h"
#include "libgenl.h"

#include "../../nshkmod.h"


/* netlink socket */
static struct rtnl_handle genl_rth;
static int genl_family = -1;

struct nsh_param {
	__u32 ifindex;
	__u32 spi;
	__u8 si;
	__u32 remote_ip, local_ip;
	__u8 encap_type;
	__u32 vni;

	int f_spisi;
	int f_dev;
	int f_remote;
};

static void usage (void) __attribute ((noreturn));

static int
parse_args (int argc, char ** argv, struct nsh_param * p)
{
	if (argc < 1)
		usage ();

	memset (p, 0, sizeof (*p));

	while (argc > 0) {
		if (strcmp (*argv, "dev") == 0) {
			NEXT_ARG ();
			p->ifindex = if_nametoindex (*argv);
			if (!p->ifindex) {
				invarg ("invalid device\n", *argv);
				exit (-1);
			}
			p->f_dev++;
		} else if (strcmp (*argv, "spi") == 0)  {
			NEXT_ARG ();
			if (get_u32 (&p->spi, *argv, 0)) {
				invarg ("invalid spi\n", * argv);
				exit (-1);
			}
			p->f_spisi++;
		} else if (strcmp (*argv, "si") == 0)  {
			NEXT_ARG ();
			if (get_u8 (&p->si, *argv, 0)) {
				invarg ("invalid si\n", * argv);
				exit (-1);
			}
			p->f_spisi++;
		} else if (strcmp (*argv, "remote") == 0)  {
			NEXT_ARG ();
			if (inet_pton (AF_INET, *argv, &p->remote_ip) < 1) {
				invarg ("invalid remote address\n", *argv);
				exit (-1);
			}
			p->f_remote++;
		} else if (strcmp (*argv, "local") == 0)  {
			NEXT_ARG ();
			if (inet_pton (AF_INET, *argv, &p->local_ip) < 1) {
				invarg ("invalid local address\n", *argv);
				exit (-1);
			}
			p->f_remote++;
		} else if (strcmp (*argv, "encap") == 0)  {
			NEXT_ARG ();
			if (strcmp (*argv, "vxlan") == 0)
				p->encap_type = NSH_ENCAP_TYPE_VXLAN;
			else {
				invarg ("invalid encap type\n", *argv);
				exit (-1);
			}
			p->f_remote++;
		}
		argc--;
		argv++;
	}

	return 0;
}

static void
usage (void)
{
	fprintf (stderr,
		 "\n"
		 "usage:  ip nsh [ { add | del }\n"
		 "               [ spi SPI ]\n"
		 "               [ si SI ]\n"
		 "              { [ remote REMOTEIP ]\n"
		 "                [ local LOCALIP ]\n"
		 "                [ encap { vxlan [ vni VNI ] } ]\n"
		 "              | [ dev IFNAME ] }\n"
		 "        ip nsh show [ dev ]"
		);
	exit (-1);
}

static int
do_add (int argc, char ** argv)
{
	struct nsh_param p;

	parse_args (argc, argv, &p);

	if (p.f_spisi != 2) {
		fprintf (stderr, "spi and si must be specified\n");
		exit (-1);
	}

	GENL_REQUEST (req, 1024, genl_family, 0, NSHKMOD_GENL_VERSION,
		      NSHKMOD_CMD_PATH_DST_SET, NLM_F_REQUEST | NLM_F_ACK);

	if (p.f_dev) {
		/* dst of path is device */
		addattr32 (&req.n, 1024, NSHKMOD_ATTR_IFINDEX, p.ifindex);
		addattr32 (&req.n, 1024, NSHKMOD_ATTR_SPI, p.spi);
		addattr8 (&req.n, 1024, NSHKMOD_ATTR_SI, p.si);
	} else if (p.f_remote == 3) {
		/* remote, local and encap_type are specified.
		 * dst of path is remote host */
		addattr32 (&req.n, 1024, NSHKMOD_ATTR_SPI, p.spi);
		addattr8 (&req.n, 1024, NSHKMOD_ATTR_SI, p.si);
		addattr32 (&req.n, 1024, NSHKMOD_ATTR_REMOTE, p.remote_ip);
		addattr32 (&req.n, 1024, NSHKMOD_ATTR_LOCAL, p.local_ip);
		addattr8 (&req.n, 1024, NSHKMOD_ATTR_ENCAP, p.encap_type);
		if (p.vni) {
			addattr32 (&req.n, 1024, NSHKMOD_ATTR_VNI, p.vni);
		}
	}

	if (rtnl_talk (&genl_rth, &req.n, 0, 0, NULL) < 0)
		return -2;

	return 0;
}

static int
do_del (int argc, char ** argv)
{
	struct nsh_param p;

	parse_args (argc, argv, &p);

	if (p.f_spisi != 2) {
		fprintf (stderr, "spi and si must be specified\n");
		exit (-1);
	}

	GENL_REQUEST (req, 1024, genl_family, 0, NSHKMOD_GENL_VERSION,
		      NSHKMOD_CMD_PATH_DST_SET, NLM_F_REQUEST | NLM_F_ACK);

	addattr32 (&req.n, 1024, NSHKMOD_ATTR_SPI, p.spi);
	addattr8 (&req.n, 1024, NSHKMOD_ATTR_SI, p.si);

	if (rtnl_talk (&genl_rth, &req.n, 0, 0, NULL) < 0)
		return -2;

	return 0;
}

static int
dev_nlmsg (const struct sockaddr_nl * who, struct nlmsghdr * n, void * arg)
{
	return 0;
}

static int
do_show_dev (void)
{
	int ret;

	/* show dev->path mappings */
	GENL_REQUEST (req, 2014, genl_family, 0,
		      NSHKMOD_GENL_VERSION, NSHKMOD_CMD_DEV_DUMP,
		      NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST);

	req.n.nlmsg_seq = genl_rth.dump = ++genl_rth.seq;

	if ((ret = rtnl_send (&genl_rth, &req.n, req.n.nlmsg_len)) < 0) {
		fprintf (stderr, "%s:%d: error\n", __func__, __LINE__);
		return -2;
	}

	if (rtnl_dump_filter (&genl_rth, dev_nlmsg, NULL) < 0) {
		fprintf (stderr, "Dump terminated\n");
		exit (1);
	}

	return 0;
}

static int
path_nlmsg (const struct sockaddr_nl * who, struct nlmsghdr * n, void * arg)
{
	int len;
	char remote[16], local[16], encap[16], devname[IF_NAMESIZE];
	struct genlmsghdr * ghdr;
	struct rtattr * attrs[NSHKMOD_ATTR_MAX + 1];
	__u32 spi, ifindex, vni, tmp;
	__u8 si, encap_type;

	if (n->nlmsg_type == NLMSG_ERROR)
		return -EBADMSG;

	ghdr = NLMSG_DATA (n);
	len = n->nlmsg_len - NLMSG_LENGTH (sizeof (*ghdr));
	if (len < 0)
		return -1;

	parse_rtattr (attrs, NSHKMOD_ATTR_MAX,
		      (void *) ghdr + GENL_HDRLEN, len);

	if (!attrs[NSHKMOD_ATTR_SPI] || !attrs[NSHKMOD_ATTR_SI])
		return -1;

	spi = rta_getattr_u32 (attrs[NSHKMOD_ATTR_SPI]);
	si = rta_getattr_u8 (attrs[NSHKMOD_ATTR_SI]);

	if (attrs[NSHKMOD_ATTR_IFINDEX]) {
		/* dst is device */
		ifindex = rta_getattr_u32 (attrs[NSHKMOD_ATTR_IFINDEX]);
		if (!if_indextoname (ifindex, devname))
			return -1;

		fprintf (stdout, "spi %u si %u dev %s", spi, si, devname);
		return 0;
	}

	/* dst is remote host */
	if (attrs[NSHKMOD_ATTR_REMOTE]) {
		tmp = rta_getattr_u32 (attrs[NSHKMOD_ATTR_REMOTE]);
		if (!inet_ntop (AF_INET, &tmp, remote, sizeof (remote)))
			return -1;
	} else
		return -1;

	if (attrs[NSHKMOD_ATTR_LOCAL]) {
		tmp = rta_getattr_u32 (attrs[NSHKMOD_ATTR_LOCAL]);
		if (!inet_ntop (AF_INET, &tmp, local, sizeof (local)))
			return -1;
	} else
		return -1;

	if (attrs[NSHKMOD_ATTR_ENCAP]) {
		encap_type = rta_getattr_u8 (attrs[NSHKMOD_ATTR_ENCAP]);
		switch (encap_type) {
		case NSH_ENCAP_TYPE_VXLAN :
			strcpy (encap, "vxlan");
			break;
		case NSH_ENCAP_TYPE_ETH :
			strcpy (encap, "ether");
			break;
		case NSH_ENCAP_TYPE_GRE :
			strcpy (encap, "gre");
			break;
		case NSH_ENCAP_TYPE_GUE :
			strcpy (encap, "gue");
			break;
		}
	} else
		return -1;

	if (attrs[NSHKMOD_ATTR_VNI])
		vni = rta_getattr_u32 (attrs[NSHKMOD_ATTR_VNI]);
	else
		vni = 0;

	if (vni)
		fprintf (stdout, "spi %u si %u remote %s local %s encap %s "
			 "vni %u", spi, si, remote, local, encap, vni);
	else
		fprintf (stdout, "spi %u si %u remote %s local %s encap %s",
			 spi, si, remote, local, encap);

	return 0;
}

static int
do_show (int argc, char ** argv)
{
	int ret;

	if (*argv && strcmp (*argv, "dev") == 0) {
		return do_show_dev ();
	}

	/* show path->dst(dev/remote) mappings */
	GENL_REQUEST (req, 2014, genl_family, 0,
		      NSHKMOD_GENL_VERSION, NSHKMOD_CMD_PATH_DUMP,
		      NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST);

	req.n.nlmsg_seq = genl_rth.dump = ++genl_rth.seq;

	if ((ret = rtnl_send (&genl_rth, &req.n, req.n.nlmsg_len)) < 0) {
		fprintf (stderr, "%s:%d: error\n", __func__, __LINE__);
		return -2;
	}

	if (rtnl_dump_filter (&genl_rth, path_nlmsg, NULL) < 0) {
		fprintf (stderr, "Dump terminated\n");
		exit (1);
	}

	return 0;
}

int
do_ipnsh (int argc, char ** argv)
{
	if (genl_family < 0) {
		if (rtnl_open_byproto (&genl_rth, 0, NETLINK_GENERIC)< 0) {
			fprintf (stderr, "Can't open genetlink socket\n");
			exit (1);
		}
		genl_family = genl_resolve_family (&genl_rth,
						   NSHKMOD_GENL_NAME);
		if (genl_family < 0)
			exit (1);
	}

	if (argc < 1)
		usage ();

	if (matches (*argv, "add") == 0)
		return do_add (argc - 1, argv + 1);
	if (matches (*argv, "del") == 0 || matches (*argv, "delete") == 0)
		return do_del (argc - 1, argv + 1);
	if (matches (*argv, "show") == 0 || matches (*argv, "list") == 0)
		return do_show (argc - 1, argv + 1);

	fprintf (stderr, "Command \"%s\" is unknown, try \"ip nsh help\".\n",
		 *argv);

	return -1;
}
