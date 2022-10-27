// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2022 SASANO Takayoshi <uaa@uaa.org.uk>

#ifndef AX25_H
#define AX25_H

#include <stdint.h>
#include <stdbool.h>

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
#define PID_ARPA_ARP 0xcd

struct kissheader {
	uint8_t command;
	struct ax25header h;
} __attribute__((packed));

bool ax25_set_callsign(struct ax25callsign *c, char *str);
int ax25_match_callsign(struct ax25callsign *c1, struct ax25callsign *c2);
int ax25_check_address_field(struct ax25header *h);
int ax25_get_callsign(struct ax25callsign *c, char *str, int len);
void ether2ax25call(struct ax25callsign *c, uint8_t *addr);
void ax25call2ether(uint8_t *addr, struct ax25callsign *c);

extern uint8_t etheraddr_0th_octet;

#endif
