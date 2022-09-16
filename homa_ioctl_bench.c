#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include "homa.h"

// gcc homa_ioctl_bench.c homa_api.c -o homa_ioctl_bench && time ./homa_ioctl_bench

int main(int argc, char *argv[], char *envp[])
{
	int homa_sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_HOMA);
	char buf[999999];
	sockaddr_in_union addr = {};
	uint64_t id;

	errno = 0;
	for(int i = 0; i < 100000000; i++) {
		homa_send(homa_sockfd, buf, sizeof(buf), &addr, &id, 0);
		if (errno) {
			perror("homa_send");
			return 1;
		}
	}
}
