// This is a scratch file used for writing temporary code to test
// how it works. It has no long term value.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>

int main(int argc, char** argv) {
//	int value;
//	if (argc >= 2) {
//		sscanf(argv[1], "%x", &value);
//	} else {
//		value = 0x12345;
//	}
	
	printf("sizeof ssize_t: %ld, sizeof size_t: %ld\n", sizeof(ssize_t),
		sizeof(size_t));
	return 0;
}

