#ifndef _NSHKMOD_H_
#define _NSHKOMD_H_

/*
 * nshkmod.h
 *
 * based on draft-ietf-sfc-nsh-01
 * https://tools.ietf.org/html/draft-ietf-sfc-nsh-01
 *
 * header format.
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


struct nsh_base {
	__u8	flags;	/* Ver, O, C, Rx4 */
	__u8	length;	/* Rx2, Length*/
	__u8	mdtype;
	__u8	protocol;
};
#define NSH_BASE_CHECK_VERSION(f, v) ((f) & 0xC0 == v)
#define NSH_BASE_OAM(f) ((f) & 0x20)
#define NSH_BASE_CRITCAL(f) ((f) & 0x10)
#define NSH_BASE_LENGTH(l) ((l) | 0x3F)

#define NSH_BASE_MDTYPE1	0x01
#define NSH_BASE_MDTYPE2	0x02

#define NSH_BASE_PROTO_IPV4	0x01	/* XXX: not supported */
#define NSH_BASE_PROTO_IPV6	0x02	/* XXX: not supported */
#define NSH_BASE_PROTO_ETH	0x03


struct nsh_path {
	__u8	spi[3];
	__u8	si;
};

struct nsh_ctx_type1 {
	__u32	ctx[4];
};


#endif
