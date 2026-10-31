/* Copyright (c) 2019-2022 Homa Developers
 * SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+
 */

/*
 * Passive raw UDP tap, not an ordinary UDP port owner. IPv4 raw delivery
 * includes the IP header; IPv6 starts at UDP. Neither consumes the module's
 * copy. Linux may reassemble IP fragments before raw delivery.
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>

#include "raw_homa.h"

static void usage(const char *name)
{
	printf("Usage: %s [-4|-6] [--count N] [--timeout MS] [--payload]\n"
		"                  [--verify-checksum]\n"
		"  -4, -6       Tap only IPv4/IPv6; default: both (both required).\n"
		"  -c, --count  Stop after N filtered, structurally valid packets;\n"
		"               0 means unlimited (default). Malformed packets do\n"
		"               not count. No RPC-state/field-semantic validation.\n"
		"  -t, --timeout  Total monotonic deadline in milliseconds after\n"
		"               ready, not an idle timeout; 0 disables (default).\n"
		"  -p, --payload  Add payload_hex (bytes after fixed Homa header;\n"
		"                 includes any control padding).\n"
		"  -v, --verify-checksum  Verify UDP checksum, including rejecting\n"
		"                 zero; appropriate for fully checksummed raw\n"
		"                 injections. Default is unchecked: raw sockets\n"
		"                 do not expose skb checksum-offload metadata.\n"
		"  -h, --help   Show this help.\n"
		"Filters UDP source OR destination port %d. Requires CAP_NET_RAW.\n"
		"stdout: ready, packet key=value records, then summary. stderr:\n"
		"malformed family=... captured_length=... reason=... diagnostics.\n"
		"Exit 0: count reached without malformed traffic; 1: setup/I/O\n"
		"failure or count reached after malformed traffic; 2: deadline\n"
		"expired before count reached (also with unlimited count).\n"
		"Invalid lengths/types/ACK counts (and checksums with -v) are\n"
		"reported, not counted. Unrelated UDP is skipped. No UDP bind.\n"
		"Kernel IP validation/reassembly precedes the tap: invalid IP or\n"
		"incomplete fragments may never reach it. No jumbograms.\n",
		name, HOMA_UDP_PORT);
}

static int parse_number(const char *text, uint64_t maximum, uint64_t *value)
{
	char *end;
	unsigned long long parsed;

	if (*text < '0' || *text > '9')
		return -1;
	errno = 0;
	parsed = strtoull(text, &end, 10);
	if (errno || *end || parsed > maximum)
		return -1;
	*value = parsed;
	return 0;
}

static int monotonic_ms(int64_t *value)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
		fprintf(stderr, "clock_gettime: %s\n", strerror(errno));
		return -1;
	}
	*value = (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
	return 0;
}

/*
 * Return 1 for a valid, filtered packet, 0 for unrelated UDP, -1 for
 * malformed traffic. No packet byte is read before its enclosing bounds
 * have been validated. IPv6 destination is from IPV6_PKTINFO, not a bind.
 */
static int print_packet(int family, const uint8_t *buffer, size_t size,
		const struct msghdr *message, int payload, int verify_checksum,
		const char **reason)
{
	const uint8_t *udp = buffer, *source = NULL, *dest = NULL;
	const struct sockaddr_in6 *peer;
	struct in6_addr dest6;
	struct cmsghdr *cmsg;
	char source_text[INET6_ADDRSTRLEN], dest_text[INET6_ADDRSTRLEN];
	size_t udp_size = size, ip_length;
	uint16_t sport, dport, udp_length, checksum;

#define MALFORMED(why) do { *reason = (why); return -1; } while (0)
	if (family == AF_INET) {
		if (size < RAW_IPV4_HEADER)
			MALFORMED("short_ipv4");
		ip_length = (buffer[0] & 15) * 4;
		if ((buffer[0] >> 4) != 4 || ip_length < RAW_IPV4_HEADER ||
				ip_length > size)
			MALFORMED("ipv4_header_length");
		if (buffer[9] != IPPROTO_UDP)
			MALFORMED("ipv4_protocol");
		if (raw_get16(buffer + 2) != size)
			MALFORMED("ipv4_total_length");
		if (raw_get16(buffer + 6) & 0x3fff)
			MALFORMED("ipv4_fragment");
		source = buffer + 12;
		dest = buffer + 16;
		udp = buffer + ip_length;
		udp_size = size - ip_length;
	}
	/* Four bytes suffice to skip ordinary, unrelated UDP traffic. */
	if (udp_size < 4)
		MALFORMED("short_udp_ports");
	sport = raw_get16(udp);
	dport = raw_get16(udp + 2);
	if (sport != HOMA_UDP_PORT && dport != HOMA_UDP_PORT)
		return 0;
	if (message->msg_flags & MSG_TRUNC)
		MALFORMED("capture_truncated");
	if (udp_size < RAW_UDP_HEADER)
		MALFORMED("short_udp");
	udp_length = raw_get16(udp + 4);
	if (udp_length < RAW_UDP_HEADER || udp_length != udp_size)
		MALFORMED("udp_length");
	if (family == AF_INET6) {
		if (message->msg_flags & MSG_CTRUNC)
			MALFORMED("ancillary_truncated");
		if (message->msg_namelen < sizeof(*peer))
			MALFORMED("ipv6_source_missing");
		peer = (const struct sockaddr_in6 *)message->msg_name;
		if (peer->sin6_family != AF_INET6)
			MALFORMED("ipv6_source_family");
		source = (const uint8_t *)&peer->sin6_addr;
		/*
		 * CMSG macros predate const msghdr. recvmsg's control buffer is
		 * unchanged here; copy pktinfo to avoid alignment assumptions.
		 */
		for (cmsg = CMSG_FIRSTHDR((struct msghdr *)message); cmsg;
				cmsg = CMSG_NXTHDR((struct msghdr *)message, cmsg)) {
			if (cmsg->cmsg_level == IPPROTO_IPV6 &&
					cmsg->cmsg_type == IPV6_PKTINFO &&
					cmsg->cmsg_len >= CMSG_LEN(sizeof(struct in6_pktinfo))) {
				struct in6_pktinfo info;

				memcpy(&info, CMSG_DATA(cmsg), sizeof(info));
				dest6 = info.ipi6_addr;
				dest = (const uint8_t *)&dest6;
				break;
			}
		}
		if (!dest)
			MALFORMED("ipv6_destination_missing");
	}
	checksum = raw_get16(udp + 6);
	if (verify_checksum) {
		if (!checksum)
			MALFORMED("udp_checksum_zero");
		if (raw_udp_checksum(family == AF_INET6, source, dest, udp, udp_size))
			MALFORMED("udp_checksum");
	}
	*reason = raw_homa_error(udp + RAW_UDP_HEADER,
		udp_size - RAW_UDP_HEADER);
	if (*reason)
		return -1;
	if (!inet_ntop(family, source, source_text, sizeof(source_text)) ||
			!inet_ntop(family, dest, dest_text, sizeof(dest_text)))
		MALFORMED("address_format");
	printf("packet family=%d src=%s dst=%s udp_sport=%u udp_dport=%u"
		" udp_length=%u checksum=0x%04x checksum_status=%s",
		family == AF_INET ? 4 : 6, source_text, dest_text,
		sport, dport, udp_length, checksum,
		verify_checksum ? "verified" : "unchecked");
	raw_print_homa(udp + RAW_UDP_HEADER, udp_size - RAW_UDP_HEADER, payload);
	printf("\n");
	return 1;
#undef MALFORMED
}

int main(int argc, char **argv)
{
	static const struct option options[] = {
		{"count", required_argument, NULL, 'c'},
		{"timeout", required_argument, NULL, 't'},
		{"payload", no_argument, NULL, 'p'},
		{"verify-checksum", no_argument, NULL, 'v'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};
	struct pollfd fds[2] = {{.fd = -1}, {.fd = -1}};
	int families[2], family = AF_UNSPEC, num_fds = 0;
	uint64_t count = 0, timeout = 0, valid = 0, malformed = 0;
	int64_t deadline = 0, now;
	int option, payload = 0, verify_checksum = 0, status = 1, i;
	const char *completion = "error";

	while ((option = getopt_long(argc, argv, "46c:t:pvh", options, NULL)) != -1) {
		switch (option) {
		case '4':
		case '6':
			if (family != AF_UNSPEC) {
				fprintf(stderr, "Specify only one family option\n");
				return 1;
			}
			family = option == '4' ? AF_INET : AF_INET6;
			break;
		case 'c':
		case 't':
			if (parse_number(optarg, option == 'c' ? UINT64_MAX : INT_MAX,
					option == 'c' ? &count : &timeout)) {
				fprintf(stderr, "Invalid numeric argument: %s\n", optarg);
				return 1;
			}
			break;
		case 'p':
			payload = 1;
			break;
		case 'v':
			verify_checksum = 1;
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return 1;
		}
	}
	if (optind != argc) {
		usage(argv[0]);
		return 1;
	}
	setvbuf(stdout, NULL, _IOLBF, 0);
	if (family != AF_INET6)
		families[num_fds++] = AF_INET;
	if (family != AF_INET)
		families[num_fds++] = AF_INET6;
	for (i = 0; i < num_fds; i++) {
		fds[i].fd = socket(families[i], SOCK_RAW, IPPROTO_UDP);
		if (fds[i].fd < 0) {
			fprintf(stderr, "Raw IPv%d UDP socket (requires CAP_NET_RAW): %s\n",
				families[i] == AF_INET ? 4 : 6, strerror(errno));
			goto done;
		}
		fds[i].events = POLLIN;
		if (families[i] == AF_INET6) {
			int on = 1;

			/*
			 * Do NOT enable receive IPV6_CHECKSUM: optional software
			 * validation makes bad checksums observable rather than
			 * silently dropping them in the raw socket layer.
			 */
			if (setsockopt(fds[i].fd, IPPROTO_IPV6, IPV6_RECVPKTINFO,
					&on, sizeof(on)) < 0) {
				fprintf(stderr, "IPV6_RECVPKTINFO: %s\n", strerror(errno));
				goto done;
			}
		}
	}
	printf("ready family=%s port=%d count=%" PRIu64 " timeout_ms=%" PRIu64
		" verify_checksum=%d\n",
		family == AF_INET ? "4" : family == AF_INET6 ? "6" : "both",
		HOMA_UDP_PORT, count, timeout, verify_checksum);
	if (ferror(stdout)) {
		fprintf(stderr, "Cannot write ready report\n");
		goto done;
	}
	if (timeout) {
		if (monotonic_ms(&now))
			goto done;
		deadline = now + timeout;
	}
	for (;;) {
		int wait = -1, ready;

		if (timeout) {
			if (monotonic_ms(&now))
				goto done;
			if (now >= deadline) {
				completion = "timeout";
				status = 2;
				break;
			}
			wait = deadline - now;
		}
		ready = poll(fds, num_fds, wait);
		if (ready < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "poll: %s\n", strerror(errno));
			goto done;
		}
		for (i = 0; i < num_fds; i++) {
			uint8_t buffer[RAW_UDP_MAX + 1];
			struct sockaddr_storage peer;
			union {
				struct cmsghdr alignment;
				char bytes[CMSG_SPACE(sizeof(struct in6_pktinfo))];
			} control;
			struct iovec iov = {buffer, sizeof(buffer)};
			struct msghdr message = {0};
			const char *reason = NULL;
			ssize_t size;
			int result;

			if (fds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
				fprintf(stderr, "Raw IPv%d socket poll error: 0x%x\n",
					families[i] == AF_INET ? 4 : 6, fds[i].revents);
				goto done;
			}
			if (!(fds[i].revents & POLLIN))
				continue;
			message.msg_name = &peer;
			message.msg_namelen = sizeof(peer);
			message.msg_iov = &iov;
			message.msg_iovlen = 1;
			message.msg_control = control.bytes;
			message.msg_controllen = sizeof(control.bytes);
			size = recvmsg(fds[i].fd, &message, MSG_DONTWAIT);
			if (size < 0) {
				if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
					continue;
				fprintf(stderr, "recvmsg: %s\n", strerror(errno));
				goto done;
			}
			result = print_packet(families[i], buffer, size, &message,
				payload, verify_checksum, &reason);
			if (result < 0) {
				malformed++;
				fprintf(stderr, "malformed family=%d captured_length=%zd reason=%s\n",
					families[i] == AF_INET ? 4 : 6, size, reason);
			} else if (result > 0) {
				valid++;
			}
			if (ferror(stdout)) {
				fprintf(stderr, "Cannot write packet report\n");
				goto done;
			}
			if (count && valid == count) {
				status = malformed ? 1 : 0;
				completion = malformed ? "malformed" : "ok";
				goto done;
			}
		}
	}
done:
	for (i = 0; i < num_fds; i++)
		if (fds[i].fd >= 0)
			close(fds[i].fd);
	printf("summary status=%s valid=%" PRIu64 " malformed=%" PRIu64 "\n",
		completion, valid, malformed);
	if (fflush(stdout) != 0 || ferror(stdout))
		status = 1;
	return status;
}
