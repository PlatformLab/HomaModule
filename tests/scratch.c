// This is a scratch file used for writing temporary code to test
// how it works. It has no long term value.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>

#define print_type(name) printf("%s has type '%s'\n", #name, "__typeof__(name)");

int main(int argc, char** argv) {
//	int value;
//	if (argc >= 2) {
//		sscanf(argv[1], "%x", &value);
//	} else {
//		value = 0x12345;
//	}
	
	uint64_t x = 0x1234500001;
	uint64_t y = (x + 63) & ~0x3f;
	printf("x: %lx, y: %lx\n", x, y);
	return 0;
}

