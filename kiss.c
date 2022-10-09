// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2022 SASANO Takayoshi <uaa@uaa.org.uk>

/*
 * kissTUN - a simple KISS/AX.25 implementation with TUN interface
 */

#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#if defined(__linux__)
#include <linux/if.h>
#define PROTO_INET ETH_P_IP
#define PROTO_INET6 ETH_P_IPV6
#else
#if defined(__OpenBSD__) || defined(__NetBSD__)
#include <net/ethertypes.h>
#elif defined(__FreeBSD__) || defined(__DragonFly__)
#include <net/ethernet.h>
#endif
#define PROTO_INET ETHERTYPE_IP
#define PROTO_INET6 ETHERTYPE_IPV6
#endif

static uint8_t etheraddr_0th_octet = 0xfe;

struct ax25callsign {
	uint8_t callsign[6];
	uint8_t ssid;
} __attribute__((packed));

#define encode_addr_char(x) ((x) << 1)
#define decode_addr_char(x) ((x) >> 1)
#define SSID_MASK 0x1e

struct ax25header {
	struct ax25callsign dst;
	struct ax25callsign src;
	/* no digipeater supported, no plan to support */
	uint8_t control;
	uint8_t pid;
} __attribute__((packed));

#define CONTROL_UI 0x03
#define PID_ARPA_IP 0xcc

struct kissheader {
	uint8_t command;
	struct ax25header h;
} __attribute__((packed));

static struct ax25callsign ax_srccall, ax_bcastcall;
extern struct ether_addr macaddr_tap;

#define AX_BCASTCALL_DEFAULT "QST"

static bool ax25_set_callsign(struct ax25callsign *c, char *str)
{
	int i, n;

	c->ssid = 0x60;

	/* callsign */
	for (i = 0; i < sizeof(c->callsign); i++) {
		if (*str == '\0' || *str == '-')
			break;

		if (!isalnum(*str))
			goto fail;

		c->callsign[i] = encode_addr_char(toupper(*str++));
	}
	if (!i)
		goto fail;

	/* pad */
	for( ; i < sizeof(c->callsign); i++)
		c->callsign[i] = encode_addr_char(' ');

	/* ssid */
	switch (*str) {
	case '\0':
		goto success;
	case '-':
		str++;
		break;
	default:
		goto fail;
	}

	n = atoi(str);
	if (n < 0 || n > 15)
		goto fail;
	c->ssid |= encode_addr_char(n);

success:
	return false;
fail:
	return true;
}

static int ax25_match_callsign(struct ax25callsign *c1, struct ax25callsign *c2)
{
	return memcmp(c1->callsign, c2->callsign, sizeof(c1->callsign)) ||
		((c1->ssid ^ c2->ssid) & SSID_MASK);
}

static int ax25_check_address_field(struct ax25header *h)
{
	uint8_t c, *p = (uint8_t *)h;
	int i;

	/* AX.25 allows up to two repeaters, but not supported */
	c = 0;
	for (i = 0; i < offsetof(struct ax25header, control) - 1; i++)
		c |= *p++;

	/* bit[0] of the last octet is '1', others are '0' */
	return (c & 1) || !(*p & 1);
}

static int ax25_get_callsign(struct ax25callsign *c, char *str, int len)
{
	char tmp[10];	/* 123456-89 */
	int i, n, x;

	n = 0;
	for (i = 0; i < sizeof(c->callsign); i++) {
		if ((x = decode_addr_char(c->callsign[i])) <= ' ')
			break;
		
		tmp[n++] = x;
	}

	if ((x = decode_addr_char(c->ssid & SSID_MASK))) {
		tmp[n++] = '-';
		if (x >= 10)
			tmp[n++] = '0' + (x / 10);
		tmp[n++] = '0' + (x % 10);
	}

	tmp[n] = '\0';
	snprintf(str, len, "%s", tmp);

	return n;
}

/*
 * "AX.25 Transport Layer Drivers for TCP/IP" (KB2ICI, N2KBG, 1995) defines:
 *
 *     <----------------------- 48 bit ----------------------->
 *     [   0   ] [   1   ][   2   ][   3   ] [   4   ][   5   ]
 *     4444444 4 333333 333322 222222 221111 111111 000000 0000
 * MSB 7654321 0 987654 321098 765432 109876 543210 987654 3210 LSB
 *
 *     rrrrrrr p cccccc cccccc cccccc cccccc cccccc cccccc ssss
 *
 * "r"(reserved) bits are 1 and "p" bit is 1 when AX.25 path is used.
 *
 * In this utility, modified:
 *
 *     rrrrrr lm cccccc cccccc cccccc cccccc cccccc cccccc ssss
 *
 * Compatibility for normal ethernet system, "lm" bits are "10" for
 * local MAC address and unicast. "r" bits are still 1, but don't care.
 */
static bool ether2ax25call(struct ax25callsign *c, uint8_t *addr)
{
#define convert_ax25chr(x) (((x) & 0x7e) + 0x40)

	uint32_t uh, ul;

	/* check local MAC address / unicast */
	if ((addr[0] & 0x03) != 0x02)
		return true;

	uh = (addr[1] << 16) | (addr[2] << 8) | addr[3];
	ul = (addr[4] << 8) | addr[5];

	c->callsign[0] = convert_ax25chr(uh >> 17);
	c->callsign[1] = convert_ax25chr(uh >> 11);
	c->callsign[2] = convert_ax25chr(uh >> 5);
	c->callsign[3] = convert_ax25chr(uh << 1);
	c->callsign[4] = convert_ax25chr(ul >> 9);
	c->callsign[5] = convert_ax25chr(ul >> 3);
	c->ssid = (ul << 1) & 0x1e;

	return false;
}

static void ax25call2ether(uint8_t *addr, struct ax25callsign *c)
{
#define convert_etherchr(x) (((x) - 0x40) & 0x7e)

	uint32_t uh, ul;

	uh = ((convert_etherchr(c->callsign[0]) << 17) |
	      (convert_etherchr(c->callsign[1]) << 11) |
	      (convert_etherchr(c->callsign[2]) << 5) |
	      (convert_etherchr(c->callsign[3]) >> 1));
	ul = ((convert_etherchr(c->callsign[4]) << 9) |
	      (convert_etherchr(c->callsign[5]) << 3) |
	      ((c->ssid >> 1) & 0x0f));

	addr[0] = etheraddr_0th_octet;
	addr[1] = uh >> 16;
	addr[2] = uh >> 8;
	addr[3] = uh;
	addr[4] = ul >> 8;
	addr[5] = ul;

	return;
}

static void header_dump(struct kissheader *k, int len)
{
	char tmp[256], *p;
	int i;

	p = tmp;
	len = (len < sizeof(*k)) ? len : sizeof(*k);

	/* hex dump */
	for (i = 0; i < len; i++)
		p += sprintf(p, "%02X ", ((uint8_t *)k)[i]);
	if (len < sizeof(*k))
		goto fin;

	/* kiss header dump */
	p += sprintf(p, "cmd=%#x ", k->command);
	p += ax25_get_callsign(&k->h.src, p, 10);
	*p++ = '>';
	p += ax25_get_callsign(&k->h.dst, p, 10);
	*p++ = ' ';
	p += sprintf(p, "ctl=%#x pid=%#x", k->h.control, k->h.pid);
fin:
	printf("%s\n", tmp);
}

static bool ether_bcast(struct ether_header *h)
{
	int i;

	for (i = 0; i < sizeof(h->ether_dhost); i++)
		if (h->ether_dhost[i] != 0xff) return false;

	return true;
}

int ext_encode(uint8_t **buf, int *len, uint8_t *exbuf, int exlen)
{
	struct ether_header *h = (struct ether_header *)*buf;
	struct kissheader *k = (struct kissheader *)exbuf;

	if (*len < sizeof(*h) || exlen < sizeof(*k))
		goto discard;

	/* XXX IPv4 only */
	switch (ntohs(h->ether_type)) {
	case PROTO_INET:
		break;
	default:
		goto discard;
	}

	k->command = 0;
	if (ether_bcast(h))
		k->h.dst = ax_bcastcall;
	else if (ether2ax25call(&k->h.dst, h->ether_dhost))
		goto discard;
	k->h.src = ax_srccall;
	k->h.src.ssid |= 0x01; /* end of address field */
	k->h.control = CONTROL_UI;
	k->h.pid = PID_ARPA_IP;

	header_dump(k, sizeof(*k));

	/* discard ethernet header */
	*buf += sizeof(struct ether_header);
	*len -= sizeof(struct ether_header);

	return sizeof(*k);
discard:
	return -1;
}

int ext_decode(uint8_t **buf, int *len, uint8_t *exbuf, int exlen)
{
	struct ether_header *h = (struct ether_header *)exbuf;
	struct kissheader *k = (struct kissheader *)*buf;

	header_dump(k, *len);

	/* check header size */
	if (exlen < sizeof(*h) || *len < (sizeof(*k) + 1) ||
	    ax25_check_address_field(&k->h))
		goto discard;

	/* check params */
	if (k->command != 0 ||
	    k->h.control != CONTROL_UI || k->h.pid != PID_ARPA_IP)
		goto discard;

	/* remove KISS header */
	*buf += sizeof(*k);
	*len -= sizeof(*k);

	/* XXX IPv4 only */
	switch (**buf >> 4) {
	case 4:
		h->ether_type = htons(PROTO_INET);
		break;
	default:
		goto discard;
	}

	/* set ethernet address */
	ax25call2ether(h->ether_shost, &k->h.src);
	if (ax25_match_callsign(&ax_bcastcall, &k->h.dst))
		memset(h->ether_dhost, 0xff, sizeof(h->ether_dhost));
	else
		memcpy(h->ether_dhost, &macaddr_tap, sizeof(h->ether_dhost));

	return sizeof(*h);
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
		default:
			goto fail;
		}
	}

	if (src)
		goto fail;

	printf("KISS extension enabled\n");
	return false;
fail:
	printf("usage: -xs[src]\n");
	return true;
}

int encode_etheraddr(char *str, uint8_t *addr)
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

int decode_callsign(uint8_t *addr, char *str, int len)
{
	int ret = -1;
	struct ax25callsign tmp;
	
	if (ether2ax25call(&tmp, addr))
		goto fin;

	ret = ax25_get_callsign(&tmp, str, len);
fin:
	return ret;
}
