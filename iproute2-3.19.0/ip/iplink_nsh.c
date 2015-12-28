/*
 * iplink_nsh.c
 */

#include <stdio.h>
#include <string.h>

#include "rt_names.h"
#include "utils.h"
#include "ip_common.h"
#include "../../nshkmod.h"


static
void explain (void)
{
	fprintf (stderr,
		 "Usage: ... nsh [ spi SPI ] [ si SI ]\n");
}

static int
nsh_parse_opt (struct link_util * lu, int argc, char ** argv,
	       struct nlmsghdr * n)
{
	__u32 spi;
	__u8 si;
	int spi_set = 0, si_set = 0;

	while (argc > 0) {
		if (!matches (*argv, "help")) {
			explain ();
			exit (-1);
		} else if (!matches (*argv, "spi")) {
			NEXT_ARG ();
			if (get_u32 (&spi, *argv, 0) || spi >= 1u << 24) {
				invarg ("invalid spi", *argv);
				exit (-1);
			}
			spi_set = 1;
		} else if (!matches (*argv, "si")) {
			NEXT_ARG ();
			if (get_u8 (&si, *argv, 0)) {
				invarg ("invalid si", *argv);
				exit (-1);
			}
			si_set = 1;
		}
		argc--;
		argv++;
	}

	if (spi_set & si_set) {
		addattr32 (n, 1024, IFLA_NSHKMOD_SPI, spi);
		addattr8 (n, 1024, IFLA_NSHKMOD_SI, si);
	} else if (spi_set || si_set) {
		fprintf (stderr, "both spi and si are required\n");
		exit (-1);
	}

	return 0;
}

static void
nsh_print_opt (struct link_util * lu, FILE * f, struct rtattr * tb[])
{
	__u32 spi;
	__u8 si;

	if (!tb)
		return;

	if (!tb[IFLA_NSHKMOD_SPI] || !tb[IFLA_NSHKMOD_SI])
		return;

	spi = rta_getattr_u32 (tb[IFLA_NSHKMOD_SPI]);
	si = rta_getattr_u8 (tb[IFLA_NSHKMOD_SI]);

	fprintf (f, "spi %u si %u ", spi, si);

	return;
}

struct link_util nsh_link_util = {
	.id		= "nsh",
	.maxattr	= IFLA_NSHKMOD_MAX,
	.parse_opt	= nsh_parse_opt,
	.print_opt	= nsh_print_opt,
};
