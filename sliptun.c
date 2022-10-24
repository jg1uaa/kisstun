// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2022 SASANO Takayoshi <uaa@uaa.org.uk>

/*
 * slipTUN - a simple SLIP implementation with TUN interface
 *
 * reference: RFC 1055 (https://datatracker.ietf.org/doc/html/rfc1055)
 * - Nonstandard for transmission of IP datagrams over serial lines: SLIP
 */ 

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>

#if defined(__linux__)
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#define PROTO_INET ETH_P_IP
#define PROTO_INET6 ETH_P_IPV6
#else
#if defined(__OpenBSD__) || defined(__NetBSD__)
#include <net/ethertypes.h>
#elif defined(__FreeBSD__) || defined(__DragonFly__)
#include <net/ethernet.h>
#endif
#include <ifaddrs.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#define PROTO_INET ETHERTYPE_IP
#define PROTO_INET6 ETHERTYPE_IPV6
#endif

extern char *optarg;

static char *serdev = NULL;
static char *tundev = NULL;
static bool rtscts = false;
struct ether_addr macaddr_tap;

#define EXTARG_MAX 16
static int extargc = 0;
static char *extargv[EXTARG_MAX + 1] = {NULL};

enum portmode {
	NONE, SERIAL, TCP_CLIENT, TCP_SERVER,
};
static enum portmode portmode = NONE;
static int portarg;

static int fd_ser, fd_tun;
static bool die = false;

#define TCP_MAX_SOCKET 2

/*
 * OpenBSD's <net/if_tun.h> defines TUNMTU (3000) and TUNMRU (16384),
 * but there is no definition in Linux. 16Kbyte may be enough. 
 */
#define BUFSIZE 16384
#define EXBUFSIZE 384

#define END_CHAR 0xc0		/* indicates end of packet */
#define ESC_CHAR 0xdb		/* indicates byte stuffing */
#define ESCAPED_END 0xdc	/* ESC ESC_END means END data byte */
#define ESCAPED_ESC 0xdd	/* ESC ESC_ESC means ESC data byte */

struct encode_work {
	int outpos;
};

struct decode_work {
	int outpos;
	int inpos;
	bool esc;
};

__attribute__((weak)) int ext_encode(uint8_t **buf, int *len, uint8_t *exbuf, int exlen)
{
	struct ether_header *h = (struct ether_header *)*buf;

	if (*len < sizeof(*h))
		goto discard;

	/* XXX IPv4 only */
	switch (ntohs(h->ether_type)) {
	case PROTO_INET:
		break;
	default:
		goto discard;
	}

	/* simply discard ethernet header */
	*buf += sizeof(struct ether_header);
	*len -= sizeof(struct ether_header);

	return 0;
discard:
	return -1;
}

__attribute__((weak)) int ext_decode(uint8_t **buf, int *len, uint8_t *exbuf, int exlen)
{
	struct ether_header *h = (struct ether_header *)exbuf;

	if (exlen < sizeof(*h) || *len < 1)
		goto discard;

	/* XXX IPv4 only */
	switch (**buf >> 4) {
	case 4:
		h->ether_type = htons(PROTO_INET);
		break;
	default:
		goto discard;
	}

	/* remember "arp -s <IP address> ee:ee:ee:ee:ee:ee" */
	memset(h->ether_shost, 0xee, sizeof(h->ether_shost));

	/* use TAP device address (broad cast address does not work) */
	memcpy(h->ether_dhost, &macaddr_tap, sizeof(h->ether_dhost));

	return sizeof(*h);
discard:
	return -1;
}

__attribute__((weak)) bool ext_init(int argc, char *argv[])
{
	/* do nothing */
	return false;
}

static bool decode_slip_frame(uint8_t *out, int outsize, uint8_t *in, int insize, struct decode_work *w)
{
	uint8_t c;

	for (; w->inpos < insize; w->inpos++) {
		c = in[w->inpos];

		if (w->esc) {
			w->esc = false;
			if (c == ESCAPED_END) c = END_CHAR;
			else if (c == ESCAPED_ESC) c = ESC_CHAR;

			if (w->outpos < outsize)
				out[w->outpos++] = c;
		} else {
			switch (c) {
			case END_CHAR:
				if (w->outpos) {
					w->inpos++;
					return true;
				}
				break;
			case ESC_CHAR:
				w->esc = true;
				break;
			default:
				if (w->outpos < outsize)
					out[w->outpos++] = c;
				break;
			}
		}
	}

	return false;
}

static void *do_slip_rx(__attribute__((unused)) void *arg)
{
	ssize_t size;
	int exsize, n;
	uint8_t exbuf[EXBUFSIZE], buf[BUFSIZE], tun_tx[BUFSIZE], *p;
	struct decode_work w = {
		.outpos = 0,
		.inpos = 0,
		.esc = false,
	};
	struct iovec iov[] = {
		{.iov_base = NULL, .iov_len = 0},
		{.iov_base = NULL, .iov_len = 0},
	};
	int iovcnt;

	while (!die) {
		if ((size = read(fd_ser, buf, sizeof(buf))) < 1) {
			printf("slip read error\n");
			goto fin0;
		}
		w.inpos = 0;

		while (1) {
			if (!decode_slip_frame(tun_tx, sizeof(tun_tx),
					       buf, size, &w))
				break;

			p = tun_tx;
			n = w.outpos;
			if ((exsize = ext_decode(&p, &n, exbuf,
						 sizeof(exbuf))) < 0)
				goto next;

			iovcnt = 0;
			if (exsize) {
				iov[iovcnt].iov_base = exbuf;
				iov[iovcnt].iov_len = exsize;
				iovcnt++;
			}
			if (n > 0) {
				iov[iovcnt].iov_base = p;
				iov[iovcnt].iov_len = n;
				iovcnt++;
			}
			writev(fd_tun, iov, iovcnt);
		next:
			w.outpos = 0;
		}
	}

fin0:
	die = true;
	return NULL;
}

static void encode_slip_frame(uint8_t *out, int outsize, uint8_t *in, int insize, struct encode_work *w)
{
#define put_buffer(c) {if (w->outpos < outsize) out[w->outpos++] = (c);}

	int i;

	if (insize) {
		for (i = 0; i < insize; i++) {
			switch (in[i]) {
			case END_CHAR:
				put_buffer(ESC_CHAR);
				put_buffer(ESCAPED_END);
				break;
			case ESC_CHAR:
				put_buffer(ESC_CHAR);
				put_buffer(ESCAPED_ESC);
				break;
			default:
				put_buffer(in[i]);
				break;
			}
		}
	} else {
		put_buffer(END_CHAR);
	}
}

static void *do_slip_tx(__attribute__((unused)) void *arg)
{
	ssize_t size;
	int exsize, n;
	struct encode_work w;
	uint8_t exbuf[EXBUFSIZE], tun_rx[BUFSIZE], *p;
	/* END_CHAR + escaped character(2) * received size + END_CHAR */
	uint8_t buf[2 * (sizeof(exbuf) + sizeof(tun_rx)) + 2];

	while (!die) {
		if ((size = read(fd_tun, tun_rx, sizeof(tun_rx))) < 0) {
			printf("tun read error\n");
			goto fin0;
		}

		p = tun_rx;
		n = size;
		if ((exsize = ext_encode(&p, &n, exbuf, sizeof(exbuf))) < 0)
			continue;

		w.outpos = 0;
		encode_slip_frame(buf, sizeof(buf), NULL, 0, &w); // END_CHAR
		if (exsize)
			encode_slip_frame(buf, sizeof(buf), exbuf, exsize, &w);
		if (n > 0)
			encode_slip_frame(buf, sizeof(buf), p, n, &w);
		encode_slip_frame(buf, sizeof(buf), NULL, 0, &w); // END_CHAR
		write(fd_ser, buf, w.outpos);
	}

fin0:
	die = true;
	return NULL;
}

static int get_speed(int speed)
{
#if defined(B38400) && (B38400 == 38400)
	return speed;
#else
	switch (speed) {
	case 0:		return B0;
	case 50:	return B50;
	case 75:	return B75;
	case 110:	return B110;
	case 134:	return B134;
	case 150:	return B150;
	case 200:	return B200;
	case 300:	return B300;
	case 600:	return B600;
	case 1200:	return B1200;
	case 1800:	return B1800;
	case 2400:	return B2400;
	case 4800:	return B4800;
	case 9600:	return B9600;
	case 19200:	return B19200;
	case 38400:	return B38400;
#if defined(B57600)
	case 57600:	return B57600;
#endif
#if defined(B115200)
	case 115200:	return B115200;
#endif
#if defined(B230400)
	case 230400:	return B230400;
#endif
#if defined(B460800)
	case 460800:	return B460800;
#endif
#if defined(B500000)
	case 500000:	return B500000;
#endif
#if defined(B576000)
	case 576000:	return B576000;
#endif
#if defined(B921600)
	case 921600:	return B921600;
#endif
#if defined(B1000000)
	case 1000000:	return B1000000;
#endif
#if defined(B1152000)
	case 1152000:	return B1152000;
#endif
#if defined(B1500000)
	case 1500000:	return B1500000;
#endif
#if defined(B2000000)
	case 2000000:	return B2000000;
#endif
#if defined(B2500000)
	case 2500000:	return B2500000;
#endif
#if defined(B3000000)
	case 3000000:	return B3000000;
#endif
#if defined(B3500000)
	case 3500000:	return B3500000;
#endif
#if defined(B4000000)
	case 4000000:	return B4000000;
#endif
	default:	return -1;
	}
#endif
}

static int open_tun(void)
#if defined(__linux__)
{
#define TUN_DEVICE "/dev/net/tun"

	int fd;
	struct ifreq ifr;

	if ((fd = open(TUN_DEVICE, O_RDWR)) < 0)
		goto fin0;

	memset(&ifr, 0, sizeof(ifr));
	/* even if TAP mode, IFF_NO_PI adds flags/proto header */
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", tundev);
	if (ioctl(fd, TUNSETIFF, &ifr) < 0)
		goto fin1;

	goto fin0;

fin1:
	close(fd);
	fd = -1;
fin0:
	return fd;
}
#else
{
	return open(tundev, O_RDWR | O_EXCL);
}
#endif

static int get_etheraddr(void)
#if defined(__linux__)
{
	int fd, ret = -1;
	struct ifreq ifr;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		goto fin0;

	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", tundev);
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0)
		goto fin1;

	memcpy(&macaddr_tap, ifr.ifr_hwaddr.sa_data, sizeof(macaddr_tap));
	ret = 0;

fin1:
	close(fd);
fin0:
	return ret;
}
#else
{
	int ret = -1;
	char *p;
	struct ifaddrs *ifa, *ifa0;
	struct sockaddr_dl *sdl;

	p = strrchr(tundev, '/') + 1;
	if (p == NULL) p = tundev;

	if (getifaddrs(&ifa0) < 0)
		goto fin0;

	for (ifa = ifa0; ifa; ifa = ifa->ifa_next) {
		if ((sdl = (struct sockaddr_dl *)ifa->ifa_addr) == NULL ||
		    sdl->sdl_family != AF_LINK || sdl->sdl_type != IFT_ETHER)
			continue;

		if (!memcmp(p, sdl->sdl_data, sdl->sdl_nlen)) {
			memcpy(&macaddr_tap, LLADDR(sdl), sizeof(macaddr_tap));
			ret = 0;
			goto fin1;
		}
	}		

fin1:
	freeifaddrs(ifa0);
fin0:
	return ret;
}
#endif

static bool set_nonblock(int d, bool nonblock)
{
	int flags;

	return ((flags = fcntl(d, F_GETFL)) < 0 ||
		fcntl(d, F_SETFL, nonblock ?
		      (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK)) < 0);
}

static int open_serial(void)
{
	int fd;
	struct termios t;

	if ((fd = open(serdev,
		       O_RDWR | O_NOCTTY | O_EXCL | O_NONBLOCK)) < 0)
		goto fin0;

	memset(&t, 0, sizeof(t));
	cfsetospeed(&t, get_speed(portarg));
	cfsetispeed(&t, get_speed(portarg));

	t.c_cflag |= CREAD | CLOCAL | CS8;
	if (rtscts) t.c_cflag |= CRTSCTS;
	t.c_iflag = INPCK;
	t.c_oflag = 0;
	t.c_lflag = 0;
	t.c_cc[VTIME] = 0;
	t.c_cc[VMIN] = 1;

	tcflush(fd, TCIOFLUSH);
	tcsetattr(fd, TCSANOW, &t);

	if (set_nonblock(fd, false))
		goto fin1;

	goto fin0;

fin1:
	close(fd);
	fd = -1;
fin0:
	return fd;
}

static const char *inet_ntopXX(int af, const void *src, char *dst, socklen_t size)
{
	struct sockaddr_in *s4 = (struct sockaddr_in *)src;
	struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)src;

	switch (af) {
	case AF_INET:
		return inet_ntop(af, &s4->sin_addr.s_addr, dst, size);
	case AF_INET6:
		return inet_ntop(af, &s6->sin6_addr.s6_addr, dst, size);
	default:
		return strncpy(dst, "unknown", size);
	}
}

static struct addrinfo *acquire_address_info(void)
{
	struct addrinfo hints, *res;
	char tmp[16];

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_flags = AI_NUMERICSERV;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(tmp, sizeof(tmp), "%d", portarg);

	return getaddrinfo(serdev, tmp, &hints, &res) ? NULL : res;
}

static int wait_for_accept(int *list, int entries)
{
	int i, s = -1;
	struct pollfd *pfd;

	if (entries <= 0 ||
	    (pfd = calloc(sizeof(struct pollfd), entries)) == NULL)
		goto fin0;

	for (i = 0; i < entries; i++) {
		pfd[i].fd = list[i];
		pfd[i].events = POLLIN;
	}

	if (poll(pfd, entries, -1) <= 0)
		goto fin1;

	for (i = 0; i < entries; i++) {
		if (pfd[i].revents & POLLIN) {
			s = list[i];
			break;
		}
	}

fin1:
	free(pfd);
fin0:
	return s;
}

static int open_tcp_server(void)
{
	int i, s, enable = 1, fd = -1;
	int sock[TCP_MAX_SOCKET], numsock;
	struct addrinfo *res, *res0;
	struct sockaddr_storage ss;
	socklen_t ss_len;
	char addr_str[INET6_ADDRSTRLEN];

	if ((res0 = acquire_address_info()) == NULL)
		goto fin0;

	numsock = 0;
	for (res = res0; res && numsock < TCP_MAX_SOCKET;
	     res = res->ai_next) {
		if ((s = socket(res->ai_family, res->ai_socktype,
				res->ai_protocol)) < 0)
			continue;

		if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
			       &enable, sizeof(enable)) >= 0 &&
		    bind(s, res->ai_addr, res->ai_addrlen) >= 0 &&
		    listen(s, 1) >= 0 && !set_nonblock(s, true)) {
			sock[numsock++] = s;
			continue;
		}

		close(s);
	}

	while (1) {
		if ((s = wait_for_accept(sock, numsock)) < 0)
			break;

		ss_len = sizeof(ss);
		if ((fd = accept(s, (struct sockaddr *)&ss, &ss_len)) < 0)
			continue;

		/* nonblock is inherited from original socket (OpenBSD) */
		if (set_nonblock(fd, false)) {
			fd = s = -1;
			break;
		}

		inet_ntopXX(ss.ss_family, &ss, addr_str, sizeof(addr_str));
		printf("*** CONNECTED from %s\n", addr_str);
		break;
	}

	for (i = 0; i < numsock; i++)
		close(sock[i]);

	freeaddrinfo(res0);
fin0:
	return fd;
}

static int open_tcp_client(void)
{
	int s = -1;
	struct addrinfo *res, *res0;
	char addr_str[INET6_ADDRSTRLEN];

	if ((res0 = acquire_address_info()) == NULL)
		goto fin0;

	for (res = res0; res; res = res->ai_next) {
		if ((s = socket(res->ai_family, res->ai_socktype,
				 res->ai_protocol)) < 0)
			continue;

		if (connect(s, res->ai_addr, res->ai_addrlen) >= 0) {
			inet_ntopXX(res->ai_family, res->ai_addr,
				    addr_str, sizeof(addr_str));
			printf("*** CONNECTED to %s\n", addr_str);
			break;
		}

		close(s);
		s = -1;
	}

	freeaddrinfo(res0);
fin0:
	return s;
}

static int do_main(void)
{
	int ret = -1;
	pthread_t tid;

	if ((fd_tun = open_tun()) < 0) {
		printf("device open error (tun)\n");
		goto fin0;
	}
	if (get_etheraddr() < 0) {
		printf("failed to get ethernet address\n");
		goto fin1;
	}

	switch (portmode) {
	case SERIAL:
		fd_ser = open_serial();
		break;
	case TCP_CLIENT:
		fd_ser = open_tcp_client();
		break;
	case TCP_SERVER:
		fd_ser = open_tcp_server();
		break;
	default:
		fd_ser = -1;
		break;
	}
	if (fd_ser < 0) {
		printf("device open error (serial)\n");
		goto fin1;
	}

	if (pthread_create(&tid, NULL, &do_slip_tx, NULL)) {
		printf("pthread_create error\n");
		goto fin2;
	}

	do_slip_rx(NULL);

	pthread_cancel(tid);
	pthread_join(tid, NULL);
	ret = 0;

fin2:
	close(fd_ser);
fin1:
	close(fd_tun);
fin0:
	return ret;
}

int main(int argc, char *argv[])
{
	int ch;

	extargv[extargc++] = argv[0];

	while ((ch = getopt(argc, argv, "s:p:P:l:t:fx:")) != -1) {
		switch (ch) {
		case 's':
			portmode = SERIAL;
			portarg = atoi(optarg);
			break;
		case 'p':
			portmode = TCP_CLIENT;
			portarg = atoi(optarg);
			break;
		case 'P':
			portmode = TCP_SERVER;
			portarg = atoi(optarg);
			break;
		case 'l':
			serdev = optarg;
			break;
		case 't':
			tundev = optarg;
			break;
		case 'f':
			rtscts = true;
			break;
		case 'x':
			if (extargc < EXTARG_MAX)
				extargv[extargc++] = optarg;
			break;
		}
	}

	if (serdev == NULL || tundev == NULL || portmode == NONE ||
	    (portmode == SERIAL && get_speed(portarg) < 0)) {
		printf("usage: %s -s [serial speed] -l [serial device] "
		       "-t [tap device]\n", argv[0]);
		goto fin0;
	}

	if (ext_init(extargc, extargv))
		goto fin0;

	do_main();

fin0:
	return 0;
}
