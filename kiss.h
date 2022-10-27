// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2022 SASANO Takayoshi <uaa@uaa.org.uk>

#ifndef KISS_H
#define KISS_H

#include <string.h>
#include <sys/types.h>
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

/* kiss.c */
void encode_axcall(struct ax25callsign *c, uint8_t *addr);
void decode_macaddr(uint8_t *addr, struct ax25callsign *c1, struct ax25callsign *c2);
void header_dump(struct kissheader *k, int len);

/* arp.c */
int encode_arp_packet(uint8_t **buf, int *len, uint8_t *exbuf, int exlen);
int decode_arp_packet(uint8_t **buf, int *len, uint8_t *exbuf, int exlen);

/* icmpv6.c */
int icmpv6_handler(uint8_t **buf, int *len, uint8_t *exbuf, int exlen, int expos, bool encode);

#endif
