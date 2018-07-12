/* This file contains miscellaneous utility functions for the Homa protocol. */

#include "homa_impl.h"



/**
 * homa_symbol_for_type() - Returns a printable string describing a packet type.
 * @type:  A value from those defined by &homa_packet_type.
 */
char *homa_symbol_for_type(uint8_t type)
{
	static char buffer[20];
	switch (type) {
	case FULL_MESSAGE:
		return "FULL_MESSAGE";
	case MESSAGE_FRAG:
		return "DATA";
	case GRANT:
		return "GRANT";
	case RESEND:
		return "RESEND";
	case BUSY:
		return "BUSY";
	}
	
	/* Using a static buffer can produce garbled text under concurrency,
	 * but (a) it's unlikely (this code only executes if the opcode is
	 * bogus), (b) this is mostly for testing and debugging, and (c) the
	 * code below ensures that the string cannot run past the end of the
	 * buffer, so the code is safe. */
	snprintf(buffer, sizeof(buffer)-1, "UNKNOWN(%u)", type);
	buffer[sizeof(buffer)-1] = 0;
	return buffer;
}

/**
 * homa_print_header() - Print a human-readable string describing the
 * information a Homa packet header.
 * @packet:  Address of the first byte of the packet header.
 * @buffer:  Buffer in which to print string.
 * @length:  Number of bytes available at @buffer.
 * 
 * Return:   @buffer
 */
char *homa_print_header(char *packet, char *buffer, int length)
{
	char *pos = buffer;
	int space_left = length;
	struct common_header *common = (struct common_header *) packet;
	
	int result = snprintf(pos, space_left, "%s %s id %u.%llu",
		homa_symbol_for_type(common->type),
		(common->direction == FROM_CLIENT) ? "FROM_CLIENT"
					           : "FROM_SERVER",
		common->rpc_id.port, common->rpc_id.sequence);
	if ((result == length) || (result < 0)) {
		buffer[length-1] = 0;
		return buffer;
	}
	pos += result;
	space_left -= result;
	switch (common->type) {
	case FULL_MESSAGE: {
		struct full_message_header *h = (struct full_message_header *)
				packet;
		snprintf(pos, space_left, ", message_length %d",
				ntohs(h->message_length));
		break;
	}
	case MESSAGE_FRAG: {
		struct message_frag_header *h = (struct message_frag_header *)
				packet;
		snprintf(pos, space_left,
				", message_length %d, offset %d, unscheduled %d%s",
				ntohl(h->message_length), ntohl(h->offset),
				ntohl(h->unscheduled_bytes),
				h->retransmit ? " RETRANSMIT" : "");
		break;
	}
	case GRANT: {
		struct grant_header *h = (struct grant_header *) packet;
		snprintf(pos, space_left, ", offset %d, priority %u",
				ntohl(h->offset), h->priority);
		break;
	}
	case RESEND: {
		struct resend_header *h = (struct resend_header *) packet;
		snprintf(pos, space_left,
				", offset %d, length %d, priority %u%s",
				ntohl(h->offset), ntohl(h->length),
				h->priority, h->restart ? ", RESTART" : "");
		break;
	}
	case BUSY:
		/* Nothing to add here. */
		break;
	}
	buffer[length-1] = 0;
	return buffer;
}