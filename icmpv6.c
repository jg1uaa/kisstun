// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2022 SASANO Takayoshi <uaa@uaa.org.uk>

#include "kiss.h"

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

int icmpv6_handler(uint8_t **buf, int *len, uint8_t *exbuf, int exlen, int expos, bool encode)
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
