/* This file various utility functions for unit testing; this file
 * is implemented entirely in C, and accesses Homa and kernel internals.
 */

#include "homa_impl.h"
#include "ccutils.h"
#include "mock.h"

/**
 * unit_get_in_addr - Parse a string into an IPV4 host addresss
 * @s:          IPV4 host specification such as 192.168.0.1
 * 
 * Return:      The in_addr (in network order) corresponding to @s. IF
 *              s couldn't be parsed properly then 0 is returned.
 * 
 */
__be32 unit_get_in_addr(char *s)
{
	unsigned int a, b, c, d;
	if (sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
		return htonl((a<<24) + (b<<16) + (c<<8) + d);
	}
	return 0;
}

/**
 * unit_list_length() - Return the number of entries in a list (not including
 * the list header.
 * @head:   Header for the list (or any entry in the list, for that matter).
 */
int unit_list_length(struct list_head *head)
{
	struct list_head *pos;
	int count = 0;
	list_for_each(pos, head) {
		count++;
	}
	return count;
}

/**
 * unit_log_skb_list() - Append to the test log a human-readable description
 * of a list of packet buffers.
 * @packets:     Header for list of sk_buffs to print.
 * @verbose:     If non-zero, use homa_print_packet for each packet;
 *               otherwise use homa_print_packet_short.
 */
void unit_log_skb_list(struct sk_buff_head *packets, int verbose)
{
	struct sk_buff *skb;
	char buffer[200];
	
	skb_queue_walk(packets, skb) {
		if (!unit_log_empty())
			unit_log_printf("; ");
		if (verbose) {
			homa_print_packet(skb, buffer, sizeof(buffer));
		} else {
			homa_print_packet_short(skb, buffer, sizeof(buffer));
		}
		unit_log_printf("%s", buffer);
	}
}

/**
 * unit_teardown() - This function should be invoked at the end of every test.
 * It performs various cleanup operations, and it also performs a set of
 * consistency checks, such as checking for memory leaks or lost sk_buffs.
 */
void unit_teardown(void)
{
	mock_teardown();
	unit_log_clear();
}