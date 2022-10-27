// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2022 SASANO Takayoshi <uaa@uaa.org.uk>

#include "kiss.h"

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

int encode_arp_packet(uint8_t **buf, int *len, uint8_t *exbuf, int exlen)
{
	struct kissheader *k = (struct kissheader *)exbuf;
	struct arphdr_ether *src;
	struct arphdr_ax25 *dst;

	if (exlen < (sizeof(*k) + sizeof(struct arphdr_ax25)))
		goto discard;

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

int decode_arp_packet(uint8_t **buf, int *len, uint8_t *exbuf, int exlen)
{
	struct ether_header *h = (struct ether_header *)exbuf;
	struct arphdr_ax25 *src;
	struct arphdr_ether *dst;

	if (exlen < (sizeof(*h) + sizeof(struct arphdr_ether)))
		goto discard;

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
