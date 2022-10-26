// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2022 SASANO Takayoshi <uaa@uaa.org.uk>

/*
 * kissTUN - a simple KISS/AX.25 implementation with TUN interface
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h>
#if defined(__linux__)
#include <linux/if.h>
#define PROTO_INET ETH_P_IP
#define PROTO_INET6 ETH_P_IPV6
#define PROTO_ARP ETH_P_ARP
#else
#if defined(__OpenBSD__) || defined(__NetBSD__)
#include <net/ethertypes.h>
#elif defined(__FreeBSD__) || defined(__DragonFly__)
#include <net/ethernet.h>
#endif
#define PROTO_INET ETHERTYPE_IP
#define PROTO_INET6 ETHERTYPE_IPV6
#define PROTO_ARP ETHERTYPE_ARP
#endif
#include "ax25.h"

extern uint8_t etheraddr_0th_octet;
static bool noarp_dec = false;
static bool mcast_encode = false, mcast_ext = false;
static bool use_ipv6 = false;
static uint8_t loglevel = ~0;

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

struct arphdr_ether {
	struct arphdr h;
	struct ether_addr ar_sha;
	in_addr_t ar_spa;
	struct ether_addr ar_tha;
	in_addr_t ar_tpa;
} __attribute__((packed));

struct arphdr_ax25 {
	struct arphdr h;
	struct ax25callsign ar_sha;
	in_addr_t ar_spa;
	struct ax25callsign ar_tha;
	in_addr_t ar_tpa;
} __attribute__((packed));

#ifndef ARPHRD_AX25
#define ARPHRD_AX25 3
#endif

struct nd_opt_linkaddr_ether {
	struct nd_opt_hdr h;
	struct ether_addr lladdr;
} __attribute__((packed));

/*
 * Transmission of IPv6 Packets over AX.25 Networks
 *   The Source/Target Link-layer address option is defined as:
 *     Type                1 for Source Link-layer address
 *                         2 for Target Link-layer address
 *     Length              2 (in units of 8 octets)
 *     Link-layer address  Callsign+SSID in AX.25 style (7 octets)
 *     Padding             filled by zero (7 octets)
 */
struct nd_opt_linkaddr_ax25 {
	struct nd_opt_hdr h;
	struct ax25callsign lladdr;
	uint8_t pad[7];
} __attribute__((packed));

static int timestamp_dump(char *p)
{
	struct timeval tv;
	struct tm *tm;

	gettimeofday(&tv, NULL);
	tm = localtime(&tv.tv_sec);

	return sprintf(p, "%04d-%02d-%02d %02d:%02d:%02d.%03d ",
		       tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
		       tm->tm_hour, tm->tm_min, tm->tm_sec,
		       (int)(tv.tv_usec / 1000));
}

static void header_dump(struct kissheader *k, int len)
{
	int i;
	char tmp[128], *p;

	if (loglevel < 1)
		return;

	p = tmp;

	/* bad header: simply dump hex value */
	if (len < sizeof(*k) || ax25_check_address_field(&k->h)) {
		len = (len < sizeof(*k)) ? len : sizeof(*k);
		p += timestamp_dump(p);
		for (i = 0; i < len; i++)
			p += sprintf(p, "%02X ", ((uint8_t *)k)[i]);
		goto fin;
	}

	if (loglevel < 2)
		return;

	/* kiss header dump */
	p += timestamp_dump(p);
	p += sprintf(p, "cmd=0x%02x ctl=0x%02x pid=0x%02x ",
		     k->command, k->h.control, k->h.pid);
	p += ax25_get_callsign(&k->h.src, p, 10);
	*p++ = '>';
	p += ax25_get_callsign(&k->h.dst, p, 10);

fin:
	printf("%s\n", tmp);
}

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

static void encode_axcall(struct ax25callsign *c, uint8_t *addr)
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

static void decode_macaddr(uint8_t *addr, struct ax25callsign *c1, struct ax25callsign *c2)
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

static int encode_arp_packet(uint8_t **buf, int *len, uint8_t *exbuf, int exlen)
{
	struct kissheader *k = (struct kissheader *)exbuf;
	struct arphdr_ether *src;
	struct arphdr_ax25 *dst;

	k->h.pid = PID_ARPA_ARP;
	header_dump(k, sizeof(*k));

	/* remove ethernet header */
	*buf += sizeof(struct ether_header);
	*len -= sizeof(struct ether_header);
	if (*len < sizeof(*src))
		goto discard;

	src = (struct arphdr_ether *)*buf;
	if (src->h.ar_hrd != htons(ARPHRD_ETHER) ||
	    src->h.ar_pro != htons(PROTO_INET) ||
	    src->h.ar_hln != sizeof(src->ar_sha) ||
	    src->h.ar_pln != sizeof(src->ar_spa))
		goto discard;

	/* add translated arp packet after KISS header */
	dst = (struct arphdr_ax25 *)(exbuf + sizeof(*k));
	dst->h.ar_hrd = htons(ARPHRD_AX25);
	dst->h.ar_pro = htons(PID_ARPA_IP);
	dst->h.ar_hln = sizeof(dst->ar_sha);
	dst->h.ar_pln = sizeof(dst->ar_spa);
	dst->h.ar_op = src->h.ar_op;
	dst->ar_spa = src->ar_spa;
	dst->ar_tpa = src->ar_tpa;
	encode_axcall(&dst->ar_sha, (uint8_t *)&src->ar_sha);
	encode_axcall(&dst->ar_tha, (uint8_t *)&src->ar_tha);

	/* discard original packet */
	*len = 0;

	return sizeof(*k) + sizeof(*dst);
discard:
	return -1;
}

static int sizeof_icmpv6_message(struct icmp6_hdr *h)
{
	switch (h->icmp6_type) {
	case ND_ROUTER_SOLICIT:
	case ND_ROUTER_ADVERT:
		return -1; /* XXX need to support? */
	case ND_NEIGHBOR_SOLICIT:
		return sizeof(struct nd_neighbor_solicit);
	case ND_NEIGHBOR_ADVERT:
		return sizeof(struct nd_neighbor_advert);
	default:
		return 0; /* no need to translate */
	}
}

static uint32_t calc_be16sum(uint8_t *dat, int len)
{
	int i;
	uint32_t sum = 0;

	/* slow code, but data is not always 16bit-aligned */
	for (i = 0; i < len; i += 2) {
		sum += dat[i] << 8;
		if ((len - i) > 1)
			sum += dat[i + 1];
	}

	return sum;
}

static uint16_t calc_icmpv6_checksum(uint8_t *buf)
{
	uint32_t sum;
	uint16_t plen;
	struct ip6_hdr *h = (struct ip6_hdr *)buf;

	/* pseudo header */
	sum = calc_be16sum((uint8_t *)&h->ip6_src,
			   sizeof(h->ip6_src) + sizeof(h->ip6_dst));
	sum += h->ip6_ctlun.ip6_un1.ip6_un1_nxt;
	sum += (plen = ntohs(h->ip6_ctlun.ip6_un1.ip6_un1_plen));

	/* payload */
	sum += calc_be16sum(buf + sizeof(*h), plen);

	sum += sum << 16; /* use upper 16bit to ignore overflow */
	return (uint16_t)(0xffff - (sum >> 16));
}

static int encode_icmpv6_option(uint8_t **in, int *insize, uint8_t **out, int *outsize)
{
	struct nd_opt_linkaddr_ether *opt_ether;
	struct nd_opt_linkaddr_ax25 *opt_ax25;

	opt_ether = (struct nd_opt_linkaddr_ether *)*in;
	opt_ax25 = (struct nd_opt_linkaddr_ax25 *)*out;

	if (*insize < sizeof(*opt_ether) || *outsize < sizeof(*opt_ax25) ||
	    opt_ether->h.nd_opt_len != sizeof(*opt_ether) / 8)
		return true;

	encode_axcall(&opt_ax25->lladdr, (uint8_t *)&opt_ether->lladdr);
	memset(opt_ax25->pad, 0, sizeof(opt_ax25->pad));
	opt_ax25->h.nd_opt_type = opt_ether->h.nd_opt_type;
	opt_ax25->h.nd_opt_len = sizeof(*opt_ax25) / 8;

	*in += sizeof(*opt_ether);
	*out += sizeof(*opt_ax25);
	*insize -= sizeof(*opt_ether);
	*outsize -= sizeof(*opt_ax25);

	return false;
}

static int decode_icmpv6_option(uint8_t **in, int *insize, uint8_t **out, int *outsize)
{
	struct nd_opt_linkaddr_ether *opt_ether;
	struct nd_opt_linkaddr_ax25 *opt_ax25;

	opt_ax25 = (struct nd_opt_linkaddr_ax25 *)*in;
	opt_ether = (struct nd_opt_linkaddr_ether *)*out;

	if (*insize < sizeof(*opt_ax25) || *outsize < sizeof(*opt_ether) ||
	    opt_ax25->h.nd_opt_len != sizeof(*opt_ax25) / 8)
		return true;

	decode_macaddr((uint8_t *)&opt_ether->lladdr, &opt_ax25->lladdr, NULL);
	opt_ether->h.nd_opt_type = opt_ax25->h.nd_opt_type;
	opt_ether->h.nd_opt_len = sizeof(*opt_ether) / 8;

	*in += sizeof(*opt_ax25);
	*out += sizeof(*opt_ether);
	*insize -= sizeof(*opt_ax25);
	*outsize -= sizeof(*opt_ether);

	return false;
}
static bool pass_icmpv6_option(uint8_t **in, int *insize, uint8_t **out, int *outsize)
{
	struct nd_opt_hdr *h = (struct nd_opt_hdr *)*in;
	const int size = h->nd_opt_len * 8;

	if (*insize < size || *outsize < size)
		return true;

	memcpy(*out, *in, size);
	*in += size;
	*out += size;
	*insize -= size;
	*outsize -= size;

	return false;
}

static int translate_icmpv6_option(uint8_t *in, int insize, uint8_t *out, int outsize, bool encode)
{
	struct nd_opt_hdr *h;
	const int outsize0 = outsize;

	while (insize > 0) {
		h = (struct nd_opt_hdr *)in;
		if (!h->nd_opt_len)
			goto error; /* invalid length */

		switch (h->nd_opt_type) {
		case ND_OPT_SOURCE_LINKADDR:
		case ND_OPT_TARGET_LINKADDR:
			if (encode ?
			    encode_icmpv6_option(&in, &insize, &out, &outsize) :
			    decode_icmpv6_option(&in, &insize, &out, &outsize))
				goto error;
			break;
		default:
			if (pass_icmpv6_option(&in, &insize, &out, &outsize))
				goto error;
			break;
		}
	}

	return outsize0 - outsize;
error:
	return -1;
}

static int icmpv6_handler(uint8_t **buf, int *len, uint8_t *exbuf, int exlen, int expos, bool encode)
{
	int n, ofs, plen, icmp6_size;
	const int expos0 = expos;
	struct ip6_hdr *ip6_src, *ip6_dst;
	struct icmp6_hdr *icmp6_src, *icmp6_dst;

	/*
	 * *buf: address of IPv6 packet in source buffer
	 * *len: size of IPv6 packet in source buffer
	 * exbuf: address of work buffer
	 * exlen: total size of work buffer
	 * expos: used size of work buffer
	 * encode: true(ether->AX25) false(AX25->ether)
	 */

	ip6_src = (struct ip6_hdr *)*buf;
	plen = ntohs(ip6_src->ip6_ctlun.ip6_un1.ip6_un1_plen);
	if (plen < sizeof(*icmp6_src) || *len < (plen + sizeof(*ip6_src)))
		goto discard;

	icmp6_src = (struct icmp6_hdr *)(*buf + sizeof(*ip6_src));
	icmp6_size = sizeof_icmpv6_message(icmp6_src);
	if (icmp6_size == 0 || icmp6_size == plen)
		goto pass; /* no need to translate */
	else if (icmp6_size < 0 || plen < icmp6_size ||
		 (plen - icmp6_size) % 8 || calc_icmpv6_checksum(*buf))
		goto discard; /* block this message */

	/* create new ICMPv6 packet */
	ofs = icmp6_size + sizeof(*ip6_src);
	memcpy(exbuf + expos, *buf, ofs);
	expos += ofs;
	n = translate_icmpv6_option(*buf + ofs, plen - icmp6_size,
				    exbuf + expos, exlen - expos, encode);
	if (n < 0)
		goto discard;
	expos += n;

	ip6_dst = (struct ip6_hdr *)(exbuf + expos0);
	ip6_dst->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(icmp6_size + n);

	icmp6_dst = (struct icmp6_hdr *)(exbuf + expos0 + sizeof(*ip6_dst));
	icmp6_dst->icmp6_cksum = 0;
	icmp6_dst->icmp6_cksum =
		htons(calc_icmpv6_checksum((uint8_t *)ip6_dst));

	/* discard original packet */
	*len = 0;
pass:
	return expos;
discard:
	return -1;
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

	if (*len < sizeof(*h) ||
	    exlen < (sizeof(*k) + sizeof(struct arphdr_ax25)))
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

static int decode_arp_packet(uint8_t **buf, int *len, uint8_t *exbuf, int exlen)
{
	struct ether_header *h = (struct ether_header *)exbuf;
	struct arphdr_ax25 *src;
	struct arphdr_ether *dst;

	h->ether_type = htons(PROTO_ARP);

	/* remove KISS header */
	*buf += sizeof(struct kissheader);
	*len -= sizeof(struct kissheader);
	if (*len < sizeof(*src))
		goto discard;
	
	src = (struct arphdr_ax25 *)*buf;
	if (src->h.ar_hrd != htons(ARPHRD_AX25) ||
	    src->h.ar_pro != htons(PID_ARPA_IP) ||
	    src->h.ar_hln != sizeof(src->ar_sha) ||
	    src->h.ar_pln != sizeof(src->ar_spa))
		goto discard;

	/* add translated arp packet after ethernet header */
	dst = (struct arphdr_ether *)(exbuf + sizeof(*h));
	dst->h.ar_hrd = htons(ARPHRD_ETHER);
	dst->h.ar_pro = htons(PROTO_INET);
	dst->h.ar_hln = sizeof(dst->ar_sha);
	dst->h.ar_pln = sizeof(dst->ar_spa);
	dst->h.ar_op = src->h.ar_op;
	dst->ar_spa = src->ar_spa;
	dst->ar_tpa = src->ar_tpa;
	decode_macaddr((uint8_t *)&dst->ar_sha, &src->ar_sha, NULL);
	decode_macaddr((uint8_t *)&dst->ar_tha, &src->ar_tha, NULL);

	/* discard original packet */
	*len = 0;

	return sizeof(*h) + sizeof(*dst);
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

	if (exlen < (sizeof(*h) + sizeof(struct arphdr_ether)) ||
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
