// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2022 SASANO Takayoshi <uaa@uaa.org.uk>

/*
 * kissTUN - a simple KISS/AX.25 implementation with TUN interface
 */

#include <stdio.h>
#include <stdlib.h>
#include "kiss.h"

static bool noarp_dec = false;
static bool mcast_encode = false, mcast_ext = false;
static bool use_ipv6 = false;

static struct ax25callsign ax_srccall, ax_bcastcall;
extern struct ether_addr macaddr_tap __attribute__((weak));

static const struct ax25callsign ax_blank = {
	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 0x00
};
static const struct ether_addr macaddr_any = {
	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
};
static const struct ether_addr macaddr_bcast = {
	{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
};

#define AX_BCASTCALL_DEFAULT "QST"

/*
 * Multicast address encoded callsign:
 *
 * Encode/decode well-used multicast MAC address using ether2ax25call()
 * and ax25call2ether() functions. These functions do not care 0th octet;
 *
 *     zz:33:xx:xx:xx:xx (callsign starts ,P to ,_)
 *     zz:00:5e:xx:xx:xx (callsign starts `%X to `%[)
 *
 * Multicast MAC address encoded callsigns have !isalnum() characters
 * and easy to guess 0th octet by first character of callsign.
 * 
 * To clear the callsign is used as multicast MAC address,
 * replace space(0x20) to backquote(0x60).
 */
static void ax25call_mcastenc(struct ax25callsign *c)
{
	int i;

	for (i = 0; i < sizeof(c->callsign); i++) {
		if (c->callsign[i] == encode_addr_char(' '))
			c->callsign[i] = encode_addr_char('`');
	}
}

void encode_axcall(struct ax25callsign *c, uint8_t *addr)
{
	if (!memcmp(addr, &macaddr_tap, sizeof(macaddr_tap))) {
		/* my call */
		*c = ax_srccall;
	} else if (!memcmp(addr, &macaddr_bcast, sizeof(macaddr_bcast))) {
		/* broadcast */
		*c = ax_bcastcall;
	} else if (addr[0] & 0x01) {
		/* multicast */
		if (mcast_ext &&
		    ((addr[0] == 0x33 && addr[1] == 0x33) ||
		     (addr[0] == 0x01 && addr[1] == 0x00 && addr[2] == 0x5e))) {
			ether2ax25call(c, addr);
			ax25call_mcastenc(c);
		} else {
			/* treat as broadcast */
			*c = ax_bcastcall;
		}
	} else if (!memcmp(addr, &macaddr_any, sizeof(macaddr_any))) {
		/* special case: ARP uses blank (0x00) addr */
		*c = ax_blank;
	} else {
		/* others */
		ether2ax25call(c, addr);
	}
}

void decode_macaddr(uint8_t *addr, struct ax25callsign *c1, struct ax25callsign *c2)
{
	if (!ax25_match_callsign(c1, &ax_srccall)) {
		/* my call */
		memcpy(addr, &macaddr_tap, sizeof(macaddr_tap));
	} else if (!ax25_match_callsign(c1, &ax_bcastcall)) {
		/* broadcast */
		memcpy(addr, &macaddr_bcast, sizeof(macaddr_bcast));
	} else if (!memcmp(c1, &ax_blank, sizeof(ax_blank))) {
		/* special case(1): ARP uses blank (0x00) addr */
		memcpy(addr, &macaddr_any, sizeof(macaddr_any));
	} else if (noarp_dec && c2 != NULL && !ax25_match_callsign(c1, c2)) {
		/* special case(2): Linux uses src>src when ARP disabled */
		memcpy(addr, &macaddr_tap, sizeof(macaddr_tap));
	} else {
		/* others */
		ax25call2ether(addr, c1);

		/* multicast */
		if (mcast_encode && mcast_ext) {
			switch (c1->callsign[0]) {
			case encode_addr_char('`'):
				addr[0] = 0x01;
				break;
			case encode_addr_char(','):
				addr[0] = 0x33;
				break;
			}
		}
	}
}

static int encode_ip_packet(uint8_t **buf, int *len, uint8_t *exbuf, int exlen)
{
	struct kissheader *k = (struct kissheader *)exbuf;
	struct ip6_hdr *ip6;

	k->h.pid = PID_ARPA_IP;
	header_dump(k, sizeof(*k));

	/* discard ethernet header */
	*buf += sizeof(struct ether_header);
	*len -= sizeof(struct ether_header);
	if (*len < 1)
		goto discard;

	switch (**buf >> 4) {
	case 4:
		return sizeof(*k);
	case 6:
		if (!use_ipv6 || *len < sizeof(*ip6))
			goto discard;
		ip6 = (struct ip6_hdr *)*buf;
		return (ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_ICMPV6) ?
			icmpv6_handler(buf, len, exbuf, exlen,
				       sizeof(*k), true) : sizeof(*k);
	default:
		goto discard;
	}
discard:
	return -1;
}

static bool mcast_check(uint8_t *addr)
{
	if (!(addr[0] & 0x01)) {
		/* unicast */
		return false;
	} else if (!memcmp(addr, &macaddr_bcast, sizeof(macaddr_bcast))) {
		/* broadcast */
		return false;
	} else {
		/* multicast */
		return !mcast_encode;
	}
}

int ext_encode(uint8_t **buf, int *len, uint8_t *exbuf, int exlen)
{
	struct ether_header *h = (struct ether_header *)*buf;
	struct kissheader *k = (struct kissheader *)exbuf;

	if (*len < sizeof(*h) || exlen < sizeof(*k))
		goto discard;

	if (mcast_check(h->ether_dhost))
		goto discard;

	k->command = 0;
	encode_axcall(&k->h.dst, h->ether_dhost);
	encode_axcall(&k->h.src, h->ether_shost);
	k->h.src.ssid |= 0x01; /* end of address field */
	k->h.control = CONTROL_UI;

	switch (ntohs(h->ether_type)) {
	case PROTO_ARP:
		return encode_arp_packet(buf, len, exbuf, exlen);
	case PROTO_INET:
	case PROTO_INET6:
		return encode_ip_packet(buf, len, exbuf, exlen);
	default:
		goto discard;
	}
discard:
	return -1;
}

static int decode_ip_packet(uint8_t **buf, int *len, uint8_t *exbuf, int exlen)
{
	struct ether_header *h = (struct ether_header *)exbuf;
	struct ip6_hdr *ip6;

	/* remove KISS header */
	*buf += sizeof(struct kissheader);
	*len -= sizeof(struct kissheader);
	if (*len < 1)
		goto discard;

	switch (**buf >> 4) {
	case 4:
		h->ether_type = htons(PROTO_INET);
		return sizeof(*h);
	case 6:
		if (!use_ipv6 || *len < sizeof(*ip6))
			goto discard;
		h->ether_type = htons(PROTO_INET6);
		ip6 = (struct ip6_hdr *)*buf;
		return (ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_ICMPV6) ?
			icmpv6_handler(buf, len, exbuf, exlen,
				       sizeof(*h), false) : sizeof(*h);
	default:
		goto discard;
	}
discard:
	return -1;
}

int ext_decode(uint8_t **buf, int *len, uint8_t *exbuf, int exlen)
{
	struct ether_header *h = (struct ether_header *)exbuf;
	struct kissheader *k = (struct kissheader *)*buf;

	header_dump(k, *len);

	if (exlen < sizeof(*h) ||
	    *len < sizeof(*k) || ax25_check_address_field(&k->h))
		goto discard;

	if (k->command != 0 || k->h.control != CONTROL_UI)
		goto discard;

	decode_macaddr(h->ether_shost, &k->h.src, NULL);
	decode_macaddr(h->ether_dhost, &k->h.dst, &k->h.src);

	switch (k->h.pid) {
	case PID_ARPA_ARP:
		return decode_arp_packet(buf, len, exbuf, exlen);
	case PID_ARPA_IP:
		return decode_ip_packet(buf, len, exbuf, exlen);
	default:
		goto discard;
	}
discard:
	return -1;
}

bool ext_init(int argc, char *argv[])
{
	int i;
	bool src;

	if (ax25_set_callsign(&ax_bcastcall, AX_BCASTCALL_DEFAULT))
		goto fail;

	src = true;
	for (i = 1; i < argc; i++) {
		switch (argv[i][0]) {
		case 's':
			src = ax25_set_callsign(&ax_srccall, &argv[i][1]);
			break;
		case 'b':
			if (ax25_set_callsign(&ax_bcastcall, &argv[i][1]))
				goto fail;
		case 'o':
			etheraddr_0th_octet =
				(strtol(&argv[i][1], NULL, 0) & 0xfc) | 0x02;
			break;
		case 'n':
			noarp_dec = true;
			break;
		case 'q':
			loglevel = strtol(&argv[i][1], NULL, 0);
			break;
		case 'm':
			switch (argv[i][1]) {
			case 'a':
				mcast_encode = true;
				break;
			case 'x':
				mcast_ext = true;
				break;
			default:
				goto fail;
			}
			break;
		case '6':
			use_ipv6 = true;
			break;
		default:
			goto fail;
		}
	}

	if (src)
		goto fail;

	return false;
fail:
	printf("usage: %s -xs[src]\n", argv[0]);
	return true;
}
