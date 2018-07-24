/* This file consists mostly of "glue" that hooks Homa into the rest of
 * the Linux kernel. The guts of the protocol are in other files.
 */

#include "homa_impl.h"

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("John Ousterhout");
MODULE_DESCRIPTION("Homa transport protocol");
MODULE_VERSION("0.01");

/* Homa's protocol number within the IP protocol space (this is not an
 * officially allocated slot).
 */
#define IPPROTO_HOMA 140

/* Not yet sure what these variables are for */
long sysctl_homa_mem[3] __read_mostly;
int sysctl_homa_rmem_min __read_mostly;
int sysctl_homa_wmem_min __read_mostly;
atomic_long_t homa_memory_allocated;

/* Global data for Homa. */
struct homa homa;

/* This structure defines functions that handle various operations on
 * Homa sockets. These functions are relatively generic: they are called
 * to implement top-level system calls. Many of these operations can
 * be implemented by PF_INET functions that are independent of the
 * Homa protocol.
 */
const struct proto_ops homa_proto_ops = {
	.family		   = PF_INET,
	.owner		   = THIS_MODULE,
	.release	   = inet_release,
	.bind		   = homa_bind,
	.connect	   = inet_dgram_connect,
	.socketpair	   = sock_no_socketpair,
	.accept		   = sock_no_accept,
	.getname	   = inet_getname,
	.poll		   = homa_poll,
	.ioctl		   = inet_ioctl,
	.listen		   = sock_no_listen,
	.shutdown	   = sock_no_shutdown,
	.setsockopt	   = sock_common_setsockopt,
	.getsockopt	   = sock_common_getsockopt,
	.sendmsg	   = inet_sendmsg,
	.recvmsg	   = inet_recvmsg,
	.mmap		   = sock_no_mmap,
	.sendpage	   = sock_no_sendpage,
	.set_peek_off	   = sk_set_peek_off,
};

/* This structure also defines functions that handle various operations
 * on Homa sockets. However, these functions are lower-level than those
 * in homa_proto_ops: they are specific to the PF_INET protocol family,
 * and in many cases they are invoked by functions in homa_proto_ops.
 * Most of these functions have Homa-specific implementations.
 */
struct proto homa_prot = {
	.name		   = "HOMA",
	.owner		   = THIS_MODULE,
	.close		   = homa_close,
	.connect	   = ip4_datagram_connect,
	.disconnect	   = homa_disconnect,
	.ioctl		   = homa_ioctl,
	.init		   = homa_sock_init,
	.destroy	   = 0,
	.setsockopt	   = homa_setsockopt,
	.getsockopt	   = homa_getsockopt,
	.sendmsg	   = homa_sendmsg,
	.recvmsg	   = homa_recvmsg,
	.sendpage	   = homa_sendpage,
	.release_cb	   = ip4_datagram_release_cb,
	.hash		   = homa_hash,
	.unhash		   = homa_unhash,
	.rehash		   = homa_rehash,
	.get_port	   = homa_get_port,
	.memory_allocated  = &homa_memory_allocated,
	.sysctl_mem	   = sysctl_homa_mem,
	.sysctl_wmem	   = &sysctl_homa_wmem_min,
	.sysctl_rmem	   = &sysctl_homa_rmem_min,
	.obj_size	   = sizeof(struct homa_sock),
	.diag_destroy	   = homa_diag_destroy,
};

/* Describes Homa for the */
struct inet_protosw homa_protosw = {
	.type              = SOCK_DGRAM,
	.protocol          = IPPROTO_HOMA,
	.prot              = &homa_prot,
	.ops               = &homa_proto_ops,
	.flags             = INET_PROTOSW_REUSE,
};

/* This structure is used by IP to deliver incoming Homa packets to us. */
static struct net_protocol homa_protocol = {
	.early_demux =	homa_v4_early_demux,
	.early_demux_handler =	homa_v4_early_demux_handler,
	.handler =	homa_handler,
	.err_handler =	homa_err_handler,
	.no_policy =	1,
	.netns_ok =	1,
};

/**
 * homa_init(): invoked when this module is loaded into the Linux kernel
 * @return: 0 on success, otherwise a negative errno.
 */
static int __init homa_init(void) {
	int status;
	printk(KERN_NOTICE "Homa module loading\n");
	status = proto_register(&homa_prot, 1);
	if (status != 0) {
		printk(KERN_ERR "proto_register failed in homa_init: %d\n",
		    status);
		goto out;
	}
	inet_register_protosw(&homa_protosw);
	status = inet_add_protocol(&homa_protocol, IPPROTO_HOMA);
	if (status != 0) {
		printk(KERN_ERR "inet_add_protocol failed in homa_init: %d\n",
		    status);
		goto out_unregister;
	}
	
	homa.next_client_port = HOMA_MIN_CLIENT_PORT;
	INIT_LIST_HEAD(&homa.sockets);
	
	return 0;
	
out_unregister:
	inet_unregister_protosw(&homa_protosw);
	proto_unregister(&homa_prot);
out:
	return status;
}

/**
 * homa_exit(): invoked when this module is unloaded from the Linux kernel.
 */
static void __exit homa_exit(void) {
	printk(KERN_NOTICE "Homa module unloading\n");
	inet_del_protocol(&homa_protocol, IPPROTO_HOMA);
	inet_unregister_protosw(&homa_protosw);
	proto_unregister(&homa_prot);
}

module_init(homa_init);
module_exit(homa_exit);

/**
 * homa_bind() - Implements the bind system call for Homa sockets: associates
 * a well-known service port with a socket. Unlike other AF_INET protocols,
 * there is no need to invoke this system call for sockets that are only
 * used as clients.
 * @sock:     Socket on which the system call was invoked.
 * @uaddr:    Contains the desired port number.
 * @addr_len: Number of bytes in uaddr.
 * Return:    0 on success, otherwise a negative errno.
 */
int homa_bind(struct socket *sock, struct sockaddr *addr, int addr_len)
{
	struct homa_sock *hsk = homa_sk(sock->sk);
	struct homa_sock *owner;
	struct sockaddr_in *addr_in = (struct sockaddr_in *) addr;
	__u32 port;
	
	if (addr_len < sizeof(*addr_in)) {
		return -EINVAL;
	}
	if (addr_in->sin_family != AF_INET) {
		return -EAFNOSUPPORT;
	}
	port = ntohs(addr_in->sin_port);
	if ((port == 0) || (port >= HOMA_MIN_CLIENT_PORT)) {
		return -EINVAL;
	}
	owner = homa_find_socket(&homa, port);
	if ((owner != NULL) && (owner != hsk)) {
		return -EADDRINUSE;
	}
	hsk->server_port = port;
	return 0;
}

/**
 * homa_close() - Invoked when close system call is invoked on a Homa socket.
 * @sk:      Socket being closed
 * @timeout: ??
 */
void homa_close(struct sock *sk, long timeout) {
	struct homa_sock *hsk = homa_sk(sk);
	struct list_head *pos;
	
	printk(KERN_NOTICE "closing socket %d\n", hsk->client_port);
	list_del(&hsk->socket_links);
	list_for_each(pos, &hsk->client_rpcs) {
		struct homa_client_rpc *crpc = list_entry(pos,
				struct homa_client_rpc, client_rpc_links);
		homa_client_rpc_destroy(crpc);
		kfree(crpc);
	}
	list_for_each(pos, &hsk->server_rpcs) {
		struct homa_server_rpc *srpc = list_entry(pos,
				struct homa_server_rpc, server_rpc_links);
		homa_server_rpc_destroy(srpc);
		kfree(srpc);
	}
	sk_common_release(sk);
}

/**
 * homa_disconnect() - Invoked when disconnect system call is invoked on a
 * Homa socket.
 * @sk:    Socket to disconnect
 * @flags: ??
 * 
 * Return: 0 on success, otherwise a negative errno.
 */
int homa_disconnect(struct sock *sk, int flags) {
	printk(KERN_WARNING "unimplemented disconnect invoked on Homa socket\n");
	return -ENOSYS;
}

/**
 * homa_ioctl() - Implements the ioctl system call for Homa sockets.
 * @sk:    Socket on which the system call was invoked.
 * @cmd:   ??
 * @arg:   ??
 * 
 * Return: 0 on success, otherwise a negative errno.
 */
int homa_ioctl(struct sock *sk, int cmd, unsigned long arg) {
	printk(KERN_WARNING "unimplemented ioctl invoked on Homa socket\n");
	return -EINVAL;
}

/**
 * homa_sock_init() - Initialize a new Homa socket.  Invoked by the
 * socket(2) system call.
 * @sk:    Socket on which the system call was invoked.
 * 
 * Return: always 0 (success).
 */
int homa_sock_init(struct sock *sk) {
	struct homa_sock *hsk = homa_sk(sk);
	hsk->server_port = 0;
	while (1) {
		if (homa.next_client_port < HOMA_MIN_CLIENT_PORT) {
			homa.next_client_port = HOMA_MIN_CLIENT_PORT;
		}
		if (!homa_find_socket(&homa, homa.next_client_port)) {
			break;
		}
		homa.next_client_port++;
	}
	hsk->client_port = homa.next_client_port;
	homa.next_client_port++;
	hsk->next_outgoing_id = 1;
	list_add(&hsk->socket_links, &homa.sockets);
	INIT_LIST_HEAD(&hsk->client_rpcs);
	INIT_LIST_HEAD(&hsk->server_rpcs);
	INIT_LIST_HEAD(&hsk->ready_server_rpcs);
	printk(KERN_NOTICE "opened socket %d\n", hsk->client_port);
	return 0;
}

/**
 * homa_setsockopt() - Implements the getsockopt system call for Homa sockets.
 * @sk:      Socket on which the system call was invoked.
 * @level:   ??
 * @optname: Identifies a particular setsockopt operation.
 * @optval:  Address in user space of the the new value for the option.
 * @optlen:  Number of bytes of data at @optval.
 * Return:   0 on success, otherwise a negative errno.
 */
int homa_setsockopt(struct sock *sk, int level, int optname,
    char __user *optval, unsigned int optlen) {
	printk(KERN_WARNING "unimplemented setsockopt invoked on Homa socket:"
			" level %d, optname %d, optlen %d\n",
			level, optname, optlen);
	return -EINVAL;
	
}

/**
 * homa_getsockopt() - Implements the getsockopt system call for Homa sockets.
 * @sk:      Socket on which the system call was invoked.
 * @level:   ??
 * @optname: Identifies a particular setsockopt operation.
 * @optval:  Address in user space where the option's value should be stored.
 * @option:  ??.
 * Return:   0 on success, otherwise a negative errno.
 */
int homa_getsockopt(struct sock *sk, int level, int optname,
    char __user *optval, int __user *option) {
	printk(KERN_WARNING "unimplemented getsockopt invoked on Homa socket:"
			" level %d, optname %d\n", level, optname);
	return -EINVAL;
	
}

/**
 * homa_sendmsg() - Send a message on a Homa socket.
 * @sk:    Socket on which the system call was invoked.
 * @msg:   Structure describing the message to send.
 * @len:   Number of bytes of the message.
 * Return: 0 on success, otherwise a negative errno.
 */
int homa_sendmsg(struct sock *sk, struct msghdr *msg, size_t len) {
	struct inet_sock *inet = inet_sk(sk);
	struct homa_sock *hsk = homa_sk(sk);
	int err = 0;
	struct homa_client_rpc *crpc = NULL;
	
	DECLARE_SOCKADDR(struct sockaddr_in *, dest_in, msg->msg_name);
	if (msg->msg_namelen < sizeof(*dest_in))
		return -EINVAL;
	if (dest_in->sin_family != AF_INET) {
		return -EAFNOSUPPORT;
	}
	
	lock_sock(sk);
	crpc = (struct homa_client_rpc *) kmalloc(sizeof(*crpc), GFP_KERNEL);
	if (unlikely(!crpc)) {
		err = -ENOMEM;
		goto error;
	}
	crpc->id = hsk->next_outgoing_id;
	hsk->next_outgoing_id++;
	list_add(&crpc->client_rpc_links, &hsk->client_rpcs);
	
	err = homa_addr_init(&crpc->dest, sk, inet->inet_saddr,
			hsk->client_port, dest_in->sin_addr.s_addr,
			ntohs(dest_in->sin_port));
	if (unlikely(err != 0)) {
		goto error;
	}
	
	err = homa_message_out_init(&crpc->request, sk, msg, len,
			&crpc->dest, hsk->client_port, crpc->id);
        if (unlikely(err != 0)) {
		goto error;
	}
	homa_xmit_packets(&crpc->request, sk, &crpc->dest);
	release_sock(sk);
	return len;
	
error:
	if (crpc) {
		homa_client_rpc_destroy(crpc);
	}
	release_sock(sk);
	return err;
}

/**
 * homa_recvmsg() - Receive a message from a Homa socket.
 * @sk:       Socket on which the system call was invoked.
 * @msg:      Describes where to copy the message data.
 * @len:      Bytes of space still left at msg.
 * @noblock:  Non-zero means MSG_DONTWAIT was specified
 * @flags:    Flags from system call, not including MSG_DONTWAIT
 * @addr_len: Store the length of the caller address here.
 * Return:    0 on success, otherwise a negative errno.
 */
int homa_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
		 int noblock, int flags, int *addr_len) {
	DECLARE_SOCKADDR(struct sockaddr_in *, sin, msg->msg_name);
	struct homa_sock *hsk = homa_sk(sk);
	struct homa_message_in *msgin;
	int count;
	
	printk(KERN_NOTICE "Entering homa_recvmsg\n");
	while (1) {
		if (!list_empty(&hsk->ready_server_rpcs)) {
			struct homa_server_rpc *srpc;
			srpc = list_first_entry(&hsk->ready_server_rpcs,
				struct homa_server_rpc, ready_links);
			printk(KERN_NOTICE "srpc: %p\n", srpc);
			printk(KERN_NOTICE "srpc->next: %p, srpc->prev: %p\n",
				srpc->ready_links.next, srpc->ready_links.prev);
			list_del(&srpc->ready_links);
			srpc->state = IN_SERVICE;
			msgin = &srpc->request;
			if (sin) {
				sin->sin_family = AF_INET;
				sin->sin_port = htons(srpc->sport);
				sin->sin_addr.s_addr = srpc->saddr;
				memset(sin->sin_zero, 0, sizeof(sin->sin_zero));
				*addr_len = sizeof(*sin);
			}
			break;
		}
		printk(KERN_NOTICE "Leaving homa_recvmsg with EAGAIN\n");
		return -EAGAIN;
	}
	
	count =  homa_message_in_copy_data(msgin, msg, len);
	printk(KERN_NOTICE "Leaving homa_recvmsg normally\n");
	return count;
}

/**
 * homa_sendpage() - ??.
 * @sk:     Socket for the operation
 * @page:   ??
 * @offset: ??
 * @size:   ??
 * @flags:  ??
 * Return:  0 on success, otherwise a negative errno.
 */
int homa_sendpage(struct sock *sk, struct page *page, int offset,
		  size_t size, int flags) {
	printk(KERN_WARNING "unimplemented sendpage invoked on Homa socket\n");
	return -ENOSYS;
}

/**
 * homa_hash() - ??.
 * @sk:    Socket for the operation
 * Return: ??
 */
int homa_hash(struct sock *sk) {
	printk(KERN_WARNING "unimplemented hash invoked on Homa socket\n");
	return 0;
}

/**
 * homa_unhash() - ??.
 */
void homa_unhash(struct sock *sk) {
	printk(KERN_WARNING "unimplemented unhash invoked on Homa socket\n");
}

/**
 * homa_rehash() - ??.
 */
void homa_rehash(struct sock *sk) {
	printk(KERN_WARNING "unimplemented rehash invoked on Homa socket\n");
}

/**
 * homa_get_port() - ??.
 * Return: ??
 */
int homa_get_port(struct sock *sk, unsigned short snum) {
	printk(KERN_WARNING "unimplemented get_port invoked on Homa socket\n");
	return 0;
}

/**
 * homa_diag_destroy() - ??.
 * Return: ??
 */
int homa_diag_destroy(struct sock *sk, int err) {
	printk(KERN_WARNING "unimplemented diag_destroy invoked on Homa socket\n");
	return -ENOSYS;
	
}

/**
 * homa_v4_early_demux() - Invoked by IP for ??.
 * Return: Always 0?
 */
int homa_v4_early_demux(struct sk_buff *skb) {
	printk(KERN_WARNING "unimplemented early_demux invoked on Homa socket\n");
	return 0;
}

/**
 * homa_v4_early_demux_handler(): invoked by IP for ??.
 * @return: Always 0?
 */
int homa_v4_early_demux_handler(struct sk_buff *skb) {
	printk(KERN_WARNING "unimplemented early_demux_handler invoked on Homa socket\n");
	return 0;
}

/**
 * homa_handler() - Top-level input packet handler; invoked by IP when a
 * Homa packet arrives.
 * @skb:   The incoming packet.
 * Return: Always 0?
 */
int homa_handler(struct sk_buff *skb) {
	char buffer[200];
	__be32 saddr = ip_hdr(skb)->saddr;
	int length = skb->len;
	struct common_header *h = (struct common_header *) skb->data;
	struct homa_server_rpc *srpc;
	struct homa_sock *hsk;
	__u16 dport;
	
	if (length < HOMA_MAX_HEADER) {
		printk(KERN_WARNING "Homa packet from %pI4 too short: "
				"%d bytes\n", &saddr, length);
		goto discard;
	}
	printk(KERN_NOTICE "incoming Homa packet: %s\n",
			homa_print_header(skb, buffer, sizeof(buffer)));
	
	dport = htons(h->dport);
	hsk = homa_find_socket(&homa, dport);
	if (!hsk) {
		/* Eventually should return an error result to sender if
		 * it is a client.
		 */
		printk(KERN_WARNING "Homa packet from %pI4 sent to "
			"unknown port %u\n", &saddr, dport);
		goto discard;
	}
	if (dport < HOMA_MIN_CLIENT_PORT) {
		/* We are the server for this RPC. */
		srpc = homa_find_server_rpc(hsk, saddr, ntohs(h->sport), h->id);
		switch (h->type) {
		case DATA:
			homa_data_from_client(&homa, skb, hsk, srpc);
			break;
		case GRANT:
			goto discard;
		case RESEND:
			goto discard;
		case BUSY:
			goto discard;
		}
	}
	return 0;
	
    discard:
	kfree_skb(skb);
	return 0;
}

/**
 * homa_err_handler() - Invoked by IP to handle an incoming error
 * packet, such as ICMP UNREACHABLE.
 * @skb:   The incoming packet.
 * @info:  Information about the error that occurred?
 * Return: Always 0?
 */
void homa_err_handler(struct sk_buff *skb, u32 info) {
	printk(KERN_WARNING "unimplemented err_handler invoked on Homa socket\n");
}

/**
 * homa_poll() - Invoked to implement the poll system call.
 * Return: ??
 */
__poll_t homa_poll(struct file *file, struct socket *sock,
	       struct poll_table_struct *wait) {
	printk(KERN_WARNING "unimplemented poll invoked on Homa socket\n");
	return 0;
}