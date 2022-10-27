// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2022 SASANO Takayoshi <uaa@uaa.org.uk>

/*
 * call2mac - callsign -> ethernet address converter
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include "ax25.h"

extern char *optarg;
enum mode {
	NONE, ENCODE, DECODE,
};

static int encode_etheraddr(char *str, uint8_t *addr)
{
	int ret = -1;
	struct ax25callsign tmp;

	if (ax25_set_callsign(&tmp, str))
		goto fin;

	ax25call2ether(addr, &tmp);
	ret = 0;
fin:
	return ret;
}

static int decode_callsign(uint8_t *addr, char *str, int len)
{
	struct ax25callsign tmp;

	ether2ax25call(&tmp, addr);
	return ax25_get_callsign(&tmp, str, len);
}

static void encode(char *call)
{
	struct ether_addr a;
	uint8_t *addr = (uint8_t *)&a;

	if (encode_etheraddr(call, addr) < 0) {
		fprintf(stderr, "invalid callsign\n");
		return;
	}

	fprintf(stdout, "%02X:%02X:%02X:%02X:%02X:%02X\n",
		addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

static void decode(char *mac)
{
	int i;
	char call[16], *p;
	struct ether_addr a = {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
	uint8_t *addr = (uint8_t *)&a;

	p = mac;
	for (i = 0; i < sizeof(a); i++) {
		addr[i] = strtol(p, &p, 16);
		if (*p == '\0')
			break;
		if (!isalnum(*p))
			p++;
	}

	if (decode_callsign(addr, call, sizeof(call)) < 0) {
		fprintf(stderr, "invalid address\n");
		return;
	}

	fprintf(stdout, "%s\n", call);
}

int main(int argc, char *argv[])
{
	int ch;
	enum mode m = NONE;
	char *arg = NULL;

	while ((ch = getopt(argc, argv, "d:e:o:")) != -1) {
		switch (ch) {
		case 'd':
			m = DECODE;
			arg = optarg;
			break;
		case 'e':
			m = ENCODE;
			arg = optarg;
			break;
		case 'o':
			etheraddr_0th_octet =
				(strtol(optarg, NULL, 0) & 0xfc) | 0x02;
			break;
		default:
			break;
		}
	}

	switch (m) {
	case ENCODE:
		encode(arg);
		break;
	case DECODE:
		decode(arg);
		break;
	default:
		fprintf(stderr, "usage: %s -e [callsign]\n", argv[0]);
		break;
	}

	return 0;
}
