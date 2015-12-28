#ifndef _NSHKMOD_H_
#define _NSHKMOD_H_

/* nshkmod.h
 * generic netlink definition for nshkmod.
 */

/* IFLA parameter */
enum {
	IFLA_NSHKMOD_UNSPEC,
	IFLA_NSHKMOD_SPI,
	IFLA_NSHKMOD_SI,
	__IFLA_NSHKMOD_MAX
};
#define IFLA_NSHKMOD_MAX (__IFLA_NSHKMOD_MAX - 1)



#define NSHKMOD_GENL_NAME	"nshkmod"
#define NSHKMOD_GENL_VERSION	0x01


/* attrs */
enum {
	NSHKMOD_ATTR_UNSPEC,
	NSHKMOD_ATTR_IFINDEX,	/* 32bit interface index */
	NSHKMOD_ATTR_SPI,	/* 24bit service path index  */
	NSHKMOD_ATTR_SI,	/* 8bit service index */
	NSHKMOD_ATTR_MDTYPE,	/* 8bit MD-type */
	NSHKMOD_ATTR_ENCAP,	/* 8bit outer encapsulation type */
	NSHKMOD_ATTR_REMOTE,	/* 32bit IPv4 address for destination */
	NSHKMOD_ATTR_LOCAL,	/* 32bit IPv4 address for source */
	NSHKMOD_ATTR_VNI,	/* 32bit (24bit) VNI for vxlan encap */
	NSHKMOD_ATTR_ETHADDR,	/* 48bit destination mac addr */
	__NSHKMOD_ATTR_MAX,
};
#define NSHKMOD_ATTR_MAX (__NSHKMOD_ATTR_MAX)

/* NSHKMOD_ATTR_ENCAP values */
enum {
	NSH_ENCAP_TYPE_NONE,	/* destination is inner device */
	NSH_ENCAP_TYPE_VXLAN,
	NSH_ENCAP_TYPE_ETHER,
	NSH_ENCAP_TYPE_GRE,	/* not implemented */
	NSH_ENCAP_TYPE_GUE	/* not implemented */
};

/* commands */
enum {
	NSHKMOD_CMD_PATH_DST_SET,	/* set dst (ifi or remote) of path */
	NSHKMOD_CMD_PATH_DST_UNSET,	/* set dst (ifi or remote) of path */
	NSHKMOD_CMD_DEV_PATH_SET,	/* set dest path of dev */
	NSHKMOD_CMD_DEV_PATH_UNSET,	/* set dest path of dev */
	NSHKMOD_CMD_PATH_DUMP,		/* dump path information */
	NSHKMOD_CMD_DEV_DUMP,		/* dump device path info*/
	__NSHKMOD_CMD_MAX,
};
#define NSHKMOD_CMD_MAX	(__NSHKMOD_CMD_MAX - 1)

#endif
