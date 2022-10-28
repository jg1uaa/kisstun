// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2022 SASANO Takayoshi <uaa@uaa.org.uk>

#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include "kiss.h"

uint8_t loglevel = ~0;

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

void header_dump(struct kissheader *k, int len)
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
