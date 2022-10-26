// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2022 SASANO Takayoshi <uaa@uaa.org.uk>

#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ax25.h"

uint8_t etheraddr_0th_octet = 0xfe;

bool ax25_set_callsign(struct ax25callsign *c, char *str)
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

int ax25_match_callsign(struct ax25callsign *c1, struct ax25callsign *c2)
{
	return memcmp(c1->callsign, c2->callsign, sizeof(c1->callsign)) ||
		((c1->ssid ^ c2->ssid) & SSID_MASK);
}

int ax25_check_address_field(struct ax25header *h)
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

int ax25_get_callsign(struct ax25callsign *c, char *str, int len)
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
void ether2ax25call(struct ax25callsign *c, uint8_t *addr)
{
#define convert_ax25chr(x) (((x) & 0x7e) + 0x40)

	uint32_t uh, ul;

	uh = (addr[1] << 16) | (addr[2] << 8) | addr[3];
	ul = (addr[4] << 8) | addr[5];

	c->callsign[0] = convert_ax25chr(uh >> 17);
	c->callsign[1] = convert_ax25chr(uh >> 11);
	c->callsign[2] = convert_ax25chr(uh >> 5);
	c->callsign[3] = convert_ax25chr(uh << 1);
	c->callsign[4] = convert_ax25chr(ul >> 9);
	c->callsign[5] = convert_ax25chr(ul >> 3);
	c->ssid = (ul << 1) & 0x1e;
}

void ax25call2ether(uint8_t *addr, struct ax25callsign *c)
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
}
