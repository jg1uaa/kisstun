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

static struct ax25callsign ax_srccall, ax_dstcall;

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

static bool check_ipv4(uint8_t *ip)
{
	return (*ip >> 4) != 4;
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
	
int ext_encode(uint8_t **buf, int *len, uint8_t *exbuf, int exlen)
{
	struct kissheader *k = (struct kissheader *)exbuf;

	if (exlen < sizeof(*k))
		goto discard;

	k->command = 0;
	k->h.dst = ax_dstcall;
	k->h.src = ax_srccall;
	k->h.src.ssid |= 0x01; /* end of address field */
	k->h.control = CONTROL_UI;
	k->h.pid = PID_ARPA_IP;

	header_dump(k, sizeof(*k));

	/* IPv4 only */
	if (*len < 1 || check_ipv4(*buf))
		goto discard;

	return sizeof(*k);
discard:
	return -1;
}

int ext_decode(uint8_t **buf, int *len, uint8_t *exbuf, int exlen)
{
	struct kissheader *k = (struct kissheader *)*buf;

	header_dump(k, *len);

	/* check header size */
	if (*len < sizeof(*k) || ax25_check_address_field(&k->h))
		goto discard;

	/* check params */
	if (k->command != 0 ||
	    k->h.control != CONTROL_UI || k->h.pid != PID_ARPA_IP)
		goto discard;

	/* check packet from destination callsign */
	if (ax25_match_callsign(&k->h.src, &ax_dstcall))
		goto discard;

	/* remove KISS header */
	*buf += sizeof(*k);
	*len -= sizeof(*k);

	/* IPv4 only */
	if (*len < 1 || check_ipv4(*buf))
		goto discard;

	return 0;
discard:
	return -1;
}

bool ext_init(int argc, char *argv[])
{
	int i;
	bool src, dst;

	src = dst = true;
	for (i = 1; i < argc; i++) {
		switch (argv[i][0]) {
		case 's':
			src = ax25_set_callsign(&ax_srccall, &argv[1][1]);
			break;
		case 'd':
			dst = ax25_set_callsign(&ax_dstcall, &argv[2][1]);
			break;
		default:
			goto fail;
		}
	}

	if (src || dst)
		goto fail;

	printf("KISS extension enabled\n");
	return false;
fail:
	printf("usage: -xs[src] -xd[dst]\n");
	return true;
}
