/* This file contains miscellaneous utility functions for the Homa protocol. */

#include "homa_impl.h"

/**
 * homa_addr_destroy() - Destructor for homa_addr
 * @addr:     Structure to clean up.
 */
void homa_addr_destroy(struct homa_addr *addr)
{
	dst_release(addr->dst);
}

/**
 * homa_addr_init() - Constructor for homa_addr.
 * @addr:     Structure to initialize.
 * @sk:       Socket where this address will be used.
 * @saddr:    IP address of source (this machine).
 * @sport:    Port on this machine from which packets will be sent.
 * @daddr:    IP address of destination machine.
 * @dport:    Report of the destination that will handle incoming packets.
 * Return:   0 for success, otherwise negative errno.
 */
int homa_addr_init(struct homa_addr *addr, struct sock *sk, __be32 saddr,
		__u16 sport, __be32 daddr, __u16 dport)
{
	struct rtable *rt;
	
	addr->daddr = daddr;
	addr->dport = dport;
	addr->dst = NULL;
	flowi4_init_output(&addr->flow.u.ip4, sk->sk_bound_dev_if, sk->sk_mark,
			inet_sk(sk)->tos, RT_SCOPE_UNIVERSE, sk->sk_protocol,
			0, daddr, saddr, htons(dport), htons(sport),
			sk->sk_uid);
	security_sk_classify_flow(sk, &addr->flow);
	rt = ip_route_output_flow(sock_net(sk), &addr->flow.u.ip4, sk);
	if (IS_ERR(rt)) {
		return PTR_ERR(rt);
	}
	addr->dst = &rt->dst;
	return 0;
}

/**
 * homa_client_rpc_destroy() - Destructor for homa_client_rpc.
 * @crpc:  Structure to clean up.
 */
void homa_client_rpc_destroy(struct homa_client_rpc *crpc) {
	homa_addr_destroy(&crpc->dest);
	__list_del_entry(&crpc->client_rpc_links);
	homa_message_out_destroy(&crpc->request);
}

/**
 * homa_find_server_rpc() - Locate server-side information about the RPC that
 * a packet belongs to, if there is any.
 * @hsk:      Socket via which packet was received.
 * @saddr:    Address from which the packet was sent.
 * @port:     Port at @saddr from which the packet was sent.
 * @id:       Unique identifier for the RPC.
 * Return:    A pointer to the homa_server_rpc for this saddr-id combination,
 *            or NULL if none.
 */
struct homa_server_rpc *homa_find_server_rpc(struct homa_sock *hsk,
		__be32 saddr, __u16 sport, __u64 id)
{
	struct list_head *pos;
	list_for_each(pos, &hsk->server_rpcs) {
		struct homa_server_rpc *srpc = list_entry(pos,
				struct homa_server_rpc, server_rpc_links);
		if ((srpc->id == id) &&
				(srpc->sport == sport) &&
				(srpc->saddr == saddr)) {
			return srpc;
		}
	}
	return NULL;
}

/**
 * homa_find_socket() - Returns the socket associated with a given port.
 * @homa:    Overall data about the Homa protocol implementation.
 * @port:    The port of interest; may be either a &homa_sock.client_port
 *           or a &homa_sock.server_port. Must not be 0.
 * Return:   The socket that owns @port, or NULL if none. 
 */
struct homa_sock *homa_find_socket(struct homa *homa, __u16 port)
{
	struct list_head *pos;
	list_for_each(pos, &homa->sockets) {
		struct homa_sock *hsk = list_entry(pos, struct homa_sock,
				socket_links);
		if ((hsk->client_port == port) || (hsk->server_port == port)) {
			return hsk;
		}
	}
	return NULL;
}

/**
 * homa_print_header() - Print a human-readable string describing the
 * information a Homa packet header.
 * @skb:     Packet whose header information should be printed.
 * @buffer:  Buffer in which to print string.
 * @length:  Number of bytes available at @buffer.
 * Return:   @buffer
 */
char *homa_print_header(struct sk_buff *skb, char *buffer, int length)
{
	char *pos = buffer;
	int space_left = length;
	struct common_header *common = (struct common_header *) skb->data;
	
	int result = snprintf(pos, space_left, "%s from %pI4:%u, id %llu",
		homa_symbol_for_type(common->type), &ip_hdr(skb)->saddr,
		ntohs(common->sport), common->id);
	if ((result == length) || (result < 0)) {
		buffer[length-1] = 0;
		return buffer;
	}
	pos += result;
	space_left -= result;
	switch (common->type) {
	case DATA: {
		struct data_header *h = (struct data_header *)
				skb->data;
		snprintf(pos, space_left,
				", message_length %d, offset %d, unscheduled %d%s",
				ntohl(h->message_length), ntohl(h->offset),
				ntohl(h->unscheduled),
				h->retransmit ? " RETRANSMIT" : "");
		break;
	}
	case GRANT: {
		struct grant_header *h = (struct grant_header *) skb->data;
		snprintf(pos, space_left, ", offset %d, priority %u",
				ntohl(h->offset), h->priority);
		break;
	}
	case RESEND: {
		struct resend_header *h = (struct resend_header *) skb->data;
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

/**
 * homa_server_rpc_destroy() - Destructor for homa_server_rpc.
 * @crpc:  Structure to clean up.
 */
void homa_server_rpc_destroy(struct homa_server_rpc *srpc) {
	homa_message_in_destroy(&srpc->request);
}

/**
 * homa_symbol_for_type() - Returns a printable string describing a packet type.
 * @type:  A value from those defined by &homa_packet_type.
 */
char *homa_symbol_for_type(uint8_t type)
{
	static char buffer[20];
	switch (type) {
	case DATA:
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