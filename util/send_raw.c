/* Copyright (c) 2019-2022 Homa Developers
 * SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+
 */

/*
 * Inject complete, caller-supplied Homa content through raw UDP. Requires
 * CAP_NET_RAW (or root); does not create an RPC or bind a UDP tunnel socket.
 * Malformed Homa content is deliberately allowed for fault injection.
 */

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include "raw_homa.h"

static void usage(const char *name)
{
	printf("Usage: %s [-4|-6] [--hex HEX | --file PATH] host [contents]\n"
		"  -4, -6       Force IPv4/IPv6; default: first resolved address.\n"
		"  -x, --hex    Complete Homa bytes as hex pairs; whitespace and\n"
		"               colons allowed between pairs (no 0x prefixes).\n"
		"  -f, --file   Complete binary Homa content; '-' reads stdin.\n"
		"  -h, --help   Show this help.\n"
		"Without --hex/--file, legacy contents is literal text, not hex.\n"
		"No protocol argument, IP/UDP header, RPC creation, or padding.\n"
		"Outer UDP ports are fixed at HOMA_UDP_PORT (%d).\n"
		"Maximum Homa content: IPv4 65507, IPv6 65527 bytes; no jumbograms.\n"
		"IPv4: kernel IP header, selected source bound on raw socket,\n"
		"software UDP checksum. IPv6: IPV6_CHECKSUM offset 6.\n"
		"Requires root/CAP_NET_RAW. Any input/socket/send failure exits 1.\n",
		name, HOMA_UDP_PORT);
}

static int hex_digit(unsigned char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static int parse_hex(const char *text, uint8_t *bytes, size_t limit,
		size_t *length)
{
	int high = -1;

	*length = 0;
	for (; *text; text++) {
		int digit = hex_digit((unsigned char)*text);

		if (digit < 0) {
			if (high < 0 && (isspace((unsigned char)*text) ||
					*text == ':'))
				continue;
			fprintf(stderr, "Invalid hex: expected complete hex pairs\n");
			return -1;
		}
		if (high < 0) {
			high = digit;
		} else {
			if (*length == limit) {
				fprintf(stderr, "Homa content exceeds %zu bytes\n", limit);
				return -1;
			}
			bytes[(*length)++] = (high << 4) | digit;
			high = -1;
		}
	}
	if (high >= 0) {
		fprintf(stderr, "Invalid hex: odd number of digits\n");
		return -1;
	}
	return 0;
}

static int read_file(const char *path, uint8_t *bytes, size_t limit,
		size_t *length)
{
	FILE *file = strcmp(path, "-") ? fopen(path, "rb") : stdin;
	int status = 0;

	if (!file) {
		fprintf(stderr, "Cannot open %s: %s\n", path, strerror(errno));
		return -1;
	}
	/* One extra byte distinguishes exact-limit input from oversized input. */
	*length = fread(bytes, 1, limit + 1, file);
	if (ferror(file)) {
		fprintf(stderr, "Cannot read %s: %s\n", path, strerror(errno));
		status = -1;
	} else if (*length > limit) {
		fprintf(stderr, "Homa content exceeds %zu bytes\n", limit);
		status = -1;
	}
	if (file != stdin && fclose(file) != 0) {
		fprintf(stderr, "Cannot close %s: %s\n", path, strerror(errno));
		status = -1;
	}
	return status;
}

int main(int argc, char **argv)
{
	static const struct option options[] = {
		{"hex", required_argument, NULL, 'x'},
		{"file", required_argument, NULL, 'f'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};
	uint8_t packet[RAW_UDP_MAX + 1] = {0};
	struct addrinfo hints = {0}, *results = NULL, *address;
	struct sockaddr_storage source, dest;
	char service[16], source_name[NI_MAXHOST], dest_name[NI_MAXHOST];
	const char *hex = NULL, *file = NULL;
	const char *operation = NULL;
	socklen_t source_length = sizeof(source);
	socklen_t dest_length;
	size_t length, limit;
	int family = AF_UNSPEC, fd = -1, probe = -1;
	int option, status = 1, error;
	uint16_t checksum = 0;
	ssize_t sent;

	while ((option = getopt_long(argc, argv, "46x:f:h", options, NULL)) != -1) {
		switch (option) {
		case '4':
		case '6':
			if (family != AF_UNSPEC) {
				fprintf(stderr, "Specify only one family option\n");
				return 1;
			}
			family = option == '4' ? AF_INET : AF_INET6;
			break;
		case 'x':
		case 'f':
			if (hex || file) {
				fprintf(stderr, "Specify exactly one input mode\n");
				return 1;
			}
			if (option == 'x')
				hex = optarg;
			else
				file = optarg;
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return 1;
		}
	}
	if (argc - optind != ((hex || file) ? 1 : 2)) {
		usage(argv[0]);
		return 1;
	}
	hints.ai_family = family;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	snprintf(service, sizeof(service), "%d", HOMA_UDP_PORT);
	error = getaddrinfo(argv[optind], service, &hints, &results);
	if (error) {
		fprintf(stderr, "Cannot resolve %s: %s\n", argv[optind],
			gai_strerror(error));
		return 1;
	}
	for (address = results; address; address = address->ai_next)
		if (address->ai_family == AF_INET || address->ai_family == AF_INET6)
			break;
	if (!address) {
		fprintf(stderr, "No IPv4 or IPv6 destination\n");
		goto done;
	}
	family = address->ai_family;
	dest_length = address->ai_addrlen;
	memset(&dest, 0, sizeof(dest));
	memcpy(&dest, address->ai_addr, dest_length);
	limit = RAW_UDP_MAX - RAW_UDP_HEADER -
		(family == AF_INET ? RAW_IPV4_HEADER : 0);
	if (hex) {
		if (parse_hex(hex, packet + RAW_UDP_HEADER, limit, &length))
			goto done;
	} else if (file) {
		if (read_file(file, packet + RAW_UDP_HEADER, limit, &length))
			goto done;
	} else {
		length = strlen(argv[optind + 1]);
		if (length > limit) {
			fprintf(stderr, "Homa content exceeds %zu bytes\n", limit);
			goto done;
		}
		memcpy(packet + RAW_UDP_HEADER, argv[optind + 1], length);
	}

	/*
	 * The probe only selects a route/source; connect sends no datagram and
	 * never binds the tunnel port. Pin that source on the actual raw socket
	 * so its IP header and the UDP pseudo-header cannot disagree.
	 */
	operation = "source-selection socket";
	probe = socket(family, SOCK_DGRAM, IPPROTO_UDP);
	if (probe < 0)
		goto socket_error;
	operation = "source-selection connect";
	if (connect(probe, (struct sockaddr *)&dest, dest_length) < 0)
		goto socket_error;
	operation = "source-selection getsockname";
	memset(&source, 0, sizeof(source));
	if (getsockname(probe, (struct sockaddr *)&source, &source_length) < 0)
		goto socket_error;
	close(probe);
	probe = -1;
	if (family == AF_INET) {
		((struct sockaddr_in *)&source)->sin_port = 0;
		((struct sockaddr_in *)&dest)->sin_port = 0;
	} else {
		((struct sockaddr_in6 *)&source)->sin6_port = 0;
		((struct sockaddr_in6 *)&dest)->sin6_port = 0;
	}
	operation = "raw UDP socket (requires root/CAP_NET_RAW)";
	fd = socket(family, SOCK_RAW, IPPROTO_UDP);
	if (fd < 0)
		goto socket_error;
	operation = "raw source bind";
	if (bind(fd, (struct sockaddr *)&source, source_length) < 0)
		goto socket_error;
	if (family == AF_INET6) {
		int offset = 6;

		operation = "IPV6_CHECKSUM";
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_CHECKSUM, &offset,
				sizeof(offset)) < 0)
			goto socket_error;
	}
	operation = "raw destination connect";
	if (connect(fd, (struct sockaddr *)&dest, dest_length) < 0)
		goto socket_error;

	length += RAW_UDP_HEADER;
	raw_put16(packet, HOMA_UDP_PORT);
	raw_put16(packet + 2, HOMA_UDP_PORT);
	raw_put16(packet + 4, length);
	if (family == AF_INET) {
		checksum = raw_udp_checksum(0,
			(const uint8_t *)&((struct sockaddr_in *)&source)->sin_addr,
			(const uint8_t *)&((struct sockaddr_in *)&dest)->sin_addr,
			packet, length);
		if (!checksum)
			checksum = 0xffff;
		raw_put16(packet + 6, checksum);
	}
	error = getnameinfo((struct sockaddr *)&source, source_length,
		source_name, sizeof(source_name), NULL, 0, NI_NUMERICHOST);
	if (!error)
		error = getnameinfo((struct sockaddr *)&dest, dest_length,
			dest_name, sizeof(dest_name), NULL, 0, NI_NUMERICHOST);
	if (error) {
		fprintf(stderr, "Cannot format address: %s\n", gai_strerror(error));
		goto done;
	}
	operation = "raw UDP send";
	do {
		sent = send(fd, packet, length, 0);
	} while (sent < 0 && errno == EINTR);
	if (sent < 0)
		goto socket_error;
	if ((size_t)sent != length) {
		fprintf(stderr, "Short send: %zd of %zu bytes\n", sent, length);
		goto done;
	}
	printf("sent family=%d src=%s dst=%s udp_sport=%d udp_dport=%d"
		" udp_length=%zu homa_length=%zu checksum=",
		family == AF_INET ? 4 : 6, source_name, dest_name,
		HOMA_UDP_PORT, HOMA_UDP_PORT, length, length - RAW_UDP_HEADER);
	if (family == AF_INET)
		printf("0x%04x\n", checksum);
	else
		printf("kernel\n");
	if (fflush(stdout) != 0 || ferror(stdout)) {
		fprintf(stderr, "Cannot write send report\n");
		goto done;
	}
	status = 0;
	goto done;

socket_error:
	fprintf(stderr, "%s: %s\n", operation, strerror(errno));
done:
	if (fd >= 0)
		close(fd);
	if (probe >= 0)
		close(probe);
	if (results)
		freeaddrinfo(results);
	return status;
}
