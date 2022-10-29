// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2022 SASANO Takayoshi <uaa@uaa.org.uk>

#include <stddef.h>
#include "kiss.h"

#if defined(__linux__)
#define IPV4_SRC_ADDR_POS offsetof(struct iphdr, saddr)
#define IPV4_DST_ADDR_POS offsetof(struct iphdr, daddr)
#else
#define IPV4_SRC_ADDR_POS offsetof(struct ip, ip_src)
#define IPV4_DST_ADDR_POS offsetof(struct ip, ip_dst)
#endif
#define IPV6_SRC_ADDR_POS offsetof(struct ip6_hdr, ip6_src)
#define IPV6_DST_ADDR_POS offsetof(struct ip6_hdr, ip6_dst)

#define ipv4_src_addrp(ip) (&((uint8_t *)(ip))[IPV4_SRC_ADDR_POS])
#define ipv4_dst_addrp(ip) (&((uint8_t *)(ip))[IPV4_DST_ADDR_POS])
#define ipv6_src_addrp(ip) (&((uint8_t *)(ip))[IPV6_SRC_ADDR_POS])
#define ipv6_dst_addrp(ip) (&((uint8_t *)(ip))[IPV6_DST_ADDR_POS])

bool ipv4_block_mcastip(uint8_t *ip)
{
	/* block 224.0.0.0/4 (all multicast) */
	return (*ipv4_dst_addrp(ip) & 0xf0) == 0xe0;
}

bool ipv6_block_mcastip(uint8_t *ip)
{
	uint8_t *p = ipv6_dst_addrp(ip);

	/* FF02:0:0:0:0:1:FF00/104 (Solicited-Node Address) */
	const uint8_t ns[] = {
		0xff, 0x02,  0x00, 0x00,  0x00, 0x00,  0x00, 0x00,
		0x00, 0x00,  0x00, 0x01,  0xff,
	};

	/* not multicast */
	if (p[0] != 0xff)
		return false;

	/* pass NS, others block */
	return memcmp(p, ns, sizeof(ns));
}
