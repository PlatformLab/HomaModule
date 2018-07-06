// This program allocates a given amount of memory and then sleeps
// forever. It is intended to create memory pressure in order to see
// how other parts of the system react when memory runs low.
//
// Usage:
// useMemory gbytes

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char** argv) {
	int gbytes, i, j;
	
	if (argc != 2) {
		printf("Usage: %s gbytes\n", argv[0]);
		exit(1);
	}
	gbytes = strtol(argv[1], NULL, 10);
	if (gbytes == 0) {
		printf("Bad value %s; must be integer # of gbytes to allocate\n",
				argv[1]);
		exit(1);
	}
	
	// Each iteration through the following loop allocates 10^9 bytes
	// of memory and fills it with random values.
	for (i = 0; i < gbytes; i++) {
#define INTS_PER_GIG 256000000
		int *block;
		block = (int *) malloc(INTS_PER_GIG*sizeof(int));
		if (block == NULL) {
			printf("Malloc returned NULL.\n");
			exit(1);
		}
		for (j = 0; j < INTS_PER_GIG; j++) {
			block[j] = random();
		}
		printf("Memory allocated: %d gbytes\n", i+1);
	}
	while (1) {
		sleep(1000);
	}
	return 0;
}

