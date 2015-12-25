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
do_show_dev (void)
{
	return 0;
}

static int
path_nlmsg (const struct sockaddr_nl * who, struct nlmsghdr * n, void * arg)
{
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
