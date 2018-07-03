# Makefile to build various testing programs for Homa.

CFLAGS := -Wall -g

BINS := getTimeTrace homaSend receiveRaw sendRaw testTimeTrace

all: $(BINS)
	
%: %.c
	cc $(CFLAGS) $< -o $@

clean:
	rm -f $(BINS)
