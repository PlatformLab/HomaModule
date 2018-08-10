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
 * 
 * Return:    0 for success, otherwise negative errno. Note: it is safe
 *            to invoke homa_addr_destroy even after an error return.
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
 * homa_client_rpc_free() - Destructor for homa_client_rpc; also frees the
 * memory for the structure.
 * @crpc:  Structure to clean up.
 */
void homa_client_rpc_free(struct homa_client_rpc *crpc) {
	/* Before doing anything else, unlink the input message from
	 * homa->grantable_msgs. This will synchronize to ensure that
	 * homa_manage_grants doesn't access this RPC after destruction
	 * begins. The if statement below is tricky: we'd like to avoid
	 * calling homa_remove_from_grantable (because it requires global
	 * synchronization), but the if statement is not synchronized,
	 * so it must not use any information that homa_manage_grants
	 * might be changing concurrently.
	 */
	if ((crpc->state == CRPC_INCOMING) && crpc->response.scheduled)
		homa_remove_from_grantable(crpc->hsk->homa, &crpc->response);
	homa_message_in_destroy(&crpc->response);
	if (crpc->state == CRPC_READY)
		__list_del_entry(&crpc->ready_links);
	__list_del_entry(&crpc->client_rpc_links);
	homa_message_out_destroy(&crpc->request);
	homa_addr_destroy(&crpc->dest);
	kfree(crpc);
}

/**
 * homa_client_rpc_new() - Allocate and construct a homa_client_rpc.
 * @hsk:      Socket to which the RPC belongs.
 * @dest:     Address of host (ip and port) to which the RPC will be sent.
 * @length:   Size of the request message.
 * @iter:     Data for the message.
 * 
 * Return:    A printer to the newly allocated object, or a negative
 *            errno if an error occurred. 
 */
struct homa_client_rpc *homa_client_rpc_new(struct homa_sock *hsk,
		struct sockaddr_in *dest, size_t length, struct iov_iter *iter)
{
	int err;
	struct homa_client_rpc *crpc;
	crpc = (struct homa_client_rpc *) kmalloc(sizeof(*crpc), GFP_KERNEL);
	if (unlikely(!crpc))
		return ERR_PTR(-ENOMEM);
	crpc->hsk = hsk;
	err = homa_addr_init(&crpc->dest, (struct sock *) hsk,
			hsk->inet.inet_saddr, hsk->client_port,
			dest->sin_addr.s_addr, ntohs(dest->sin_port));
	if (unlikely(err != 0))
		goto error2;
	crpc->id = hsk->next_outgoing_id;
	hsk->next_outgoing_id++;
	crpc->state = CRPC_WAITING;
	err = homa_message_out_init(&crpc->request, (struct sock *) hsk, iter,
			length, &crpc->dest, hsk->client_port, crpc->id);
        if (unlikely(err != 0))
		goto error1;
	crpc->response.total_length = -1;
	list_add(&crpc->client_rpc_links, &hsk->client_rpcs);
	return crpc;
	
    error1:
	homa_addr_destroy(&crpc->dest);
    error2:
	kfree(crpc);
	return ERR_PTR(err);
}

/**
 * homa_find_client_rpc() - Locate client-side information about the RPC that
 * a packet belongs to, if there is any.
 * @hsk:      Socket via which packet was received.
 * @port:     Port from which the packet was sent.
 * @id:       Unique identifier for the RPC.
 * 
 * Return:    A pointer to the homa_client_rpc for this id, or NULL if none.
 */
struct homa_client_rpc *homa_find_client_rpc(struct homa_sock *hsk,
		__u16 sport, __u64 id)
{
	struct list_head *pos;
	list_for_each(pos, &hsk->client_rpcs) {
		struct homa_client_rpc *crpc = list_entry(pos,
				struct homa_client_rpc, client_rpc_links);
		if (crpc->id == id) {
			return crpc;
		}
	}
	return NULL;
}

/**
 * homa_destroy() -  Destructor for homa objects.
 * @homa:      Object to destroy.
 */
void homa_destroy(struct homa *homa)
{
	homa_socktab_destroy(&homa->port_map);
}

/**
 * homa_find_server_rpc() - Locate server-side information about the RPC that
 * a packet belongs to, if there is any.
 * @hsk:      Socket via which packet was received.
 * @saddr:    Address from which the packet was sent.
 * @port:     Port at @saddr from which the packet was sent.
 * @id:       Unique identifier for the RPC.
 * 
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
				(srpc->client.dport == sport) &&
				(srpc->client.daddr == saddr)) {
			return srpc;
		}
	}
	return NULL;
}

/**
 * homa_init() - Constructor for homa objects.
 * @homa:   Object to initialize.
 */
void homa_init(struct homa *homa)
{
	homa->next_client_port = HOMA_MIN_CLIENT_PORT;
	homa_socktab_init(&homa->port_map);
	
	/* Wild guesses to initialize configuration values... */
	homa->rtt_bytes = 10000;
	homa->max_sched_prio = 3;
	homa->min_sched_prio = 0;
	homa->max_overcommit = 8;
	spin_lock_init(& homa->lock);
	INIT_LIST_HEAD(&homa->grantable_msgs);
	homa->num_grantable = 0;
}

/**
 * homa_print_ipv4_addr() - Convert an IPV4 address to the standard string
 * representation.
 * @addr:    Address to convert, in network byte order.
 * @buffer:  Where to store the converted value; must have room for
 *           "255.255.255.255" plus a terminating NULL character.
 * 
 * Return:   The converted value (@buffer).
 * 
 * Note: Homa uses this function, rather than the %pI4 format specifier
 * for snprintf et al., because the kernel's version of snprintf isn't
 * available in Homa's unit test environment.
 */
char *homa_print_ipv4_addr(__be32 addr, char *buffer)
{
	__u32 a2 = ntohl(addr);
	sprintf(buffer, "%u.%u.%u.%u", (a2 >> 24) & 0xff, (a2 >> 16) & 0xff,
			(a2 >> 8) & 0xff, a2 & 0xff);
	return buffer;
}

/**
 * homa_print_packet() - Print a human-readable string describing the
 * information in a Homa packet.
 * @skb:     Packet whose information should be printed.
 * @buffer:  Buffer in which to generate the string.
 * @length:  Number of bytes available at @buffer.
 * 
 * Return:   @buffer
 */
char *homa_print_packet(struct sk_buff *skb, char *buffer, int length)
{
	char *pos = buffer;
	int space_left = length;
	char addr_buf[20];
	struct common_header *common = (struct common_header *) skb->data;
	
	int result = snprintf(pos, space_left,
		"%s from %s:%u, dport %d, id %llu, length %u",
		homa_symbol_for_type(common->type),
		homa_print_ipv4_addr(ip_hdr(skb)->saddr, addr_buf),
		ntohs(common->sport), ntohs(common->dport), common->id,
		skb->len);
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
 * homa_print_packet() - Print a human-readable string describing the
 * information in a Homa packet. This function generates a more
 * abbreviated description than home_print_packet.
 * @skb:     Packet whose information should be printed.
 * @buffer:  Buffer in which to generate the string.
 * @length:  Number of bytes available at @buffer.
 * 
 * Return:   @buffer
 */
char *homa_print_packet_short(struct sk_buff *skb, char *buffer, int length)
{
	struct common_header *common = (struct common_header *) skb->data;
	switch (common->type) {
	case DATA: {
		struct data_header *h = (struct data_header *) skb->data;
		snprintf(buffer, length, "DATA%s %d/%d",
				h->retransmit ? " retrans" : "",
				ntohl(h->offset), ntohl(h->message_length));
		break;
	}
	case GRANT: {
		struct grant_header *h = (struct grant_header *) skb->data;
		snprintf(buffer, length, "GRANT %d@%d", ntohl(h->offset),
				h->priority);
		break;
	}
	case RESEND: {
		struct resend_header *h = (struct resend_header *) skb->data;
		snprintf(buffer, length, "RESEND %d-%d@%d", ntohl(h->offset),
				ntohl(h->offset) + ntohl(h->length) - 1,
				h->priority);
		break;
	}
	case BUSY:
		snprintf(buffer, length, "BUSY");
		break;
	default:
		snprintf(buffer, length, "unknown packet type %d",
				common->type);
		break;
	}
	return buffer;
}

/**
 * homa_server_rpc_destroy() - Destructor for homa_server_rpc; also frees
 * the memory for the structure.
 * @crpc:  Structure to clean up.
 */
void homa_server_rpc_free(struct homa_server_rpc *srpc)
{
	/* Before doing anything else, unlink the input message from
	 * homa->grantable_msgs. This will synchronize to ensure that
	 * homa_manage_grants doesn't access this RPC after destruction
	 * begins. The if statement below is tricky: we'd like to avoid
	 * calling homa_remove_from_grantable (because it requires global
	 * synchronization), but the if statement is not synchronized,
	 * so it must not use any information that homa_manage_grants
	 * might be changing concurrently.
	 */
	if ((srpc->state == SRPC_INCOMING) && srpc->request.scheduled)
		homa_remove_from_grantable(srpc->hsk->homa, &srpc->request);
	homa_addr_destroy(&srpc->client);
	homa_message_in_destroy(&srpc->request);
	if (srpc->state == SRPC_RESPONSE)
		homa_message_out_destroy(&srpc->response);
	__list_del_entry(&srpc->server_rpc_links);
	if (srpc->state == SRPC_READY)
		__list_del_entry(&srpc->ready_links);
	kfree(srpc);
}

/**
 * homa_server_rpc_new() - Allocate and construct a homa_server_rpc object.
 * @hsk:    Socket that owns this RPC.
 * @source: IP address (network byte order) of the RPC's client.
 * @h:      Data packet header; used to initialize the RPC.
 * 
 * Return:  A pointer to the new object, or a negative errno if an error
            occurred.
 */
struct homa_server_rpc *homa_server_rpc_new(struct homa_sock *hsk,
		__be32 source, struct data_header *h)
{
	int err;
	struct homa_server_rpc *srpc;
	srpc = (struct homa_server_rpc *) kmalloc(sizeof(*srpc),
			GFP_KERNEL);
	if (!srpc)
		return ERR_PTR(-ENOMEM);
	srpc->hsk = hsk;
	err = homa_addr_init(&srpc->client, (struct sock *) hsk,
			hsk->inet.inet_saddr, hsk->client_port, source,
			ntohs(h->common.sport));
	if (err) {
		kfree(srpc);
		return ERR_PTR(err);
	}
	srpc->id = h->common.id;
	srpc->state = SRPC_INCOMING;
	homa_message_in_init(&srpc->request, ntohl(h->message_length),
			ntohl(h->unscheduled), 1);
	list_add(&srpc->server_rpc_links, &hsk->server_rpcs);
	return srpc;
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