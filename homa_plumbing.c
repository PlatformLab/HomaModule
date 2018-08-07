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
	.init		   = homa_socket,
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
	.early_demux =	NULL, /*homa_v4_early_demux */
	.early_demux_handler =	NULL, /* homa_v4_early_demux_handler */
	.handler =	homa_handler,
	.err_handler =	homa_err_handler,
	.no_policy =	1,
	.netns_ok =	1,
};

/**
 * homa_load(): invoked when this module is loaded into the Linux kernel
 * @return: 0 on success, otherwise a negative errno.
 */
static int __init homa_load(void) {
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

	homa_init(&homa);

	return 0;

out_unregister:
	inet_unregister_protosw(&homa_protosw);
	proto_unregister(&homa_prot);
out:
	return status;
}

/**
 * homa_unload(): invoked when this module is unloaded from the Linux kernel.
 */
static void __exit homa_unload(void) {
	printk(KERN_NOTICE "Homa module unloading\n");
	homa_destroy(&homa);
	inet_del_protocol(&homa_protocol, IPPROTO_HOMA);
	inet_unregister_protosw(&homa_protosw);
	proto_unregister(&homa_prot);
}

module_init(homa_load);
module_exit(homa_unload);

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
	struct sockaddr_in *addr_in = (struct sockaddr_in *) addr;

	if (addr_len < sizeof(*addr_in)) {
		return -EINVAL;
	}
	if (addr_in->sin_family != AF_INET) {
		return -EAFNOSUPPORT;
	}
	return homa_sock_bind(&homa.port_map, hsk, ntohs(addr_in->sin_port));
}

/**
 * homa_close() - Invoked when close system call is invoked on a Homa socket.
 * @sk:      Socket being closed
 * @timeout: ??
 */
void homa_close(struct sock *sk, long timeout) {
	struct homa_sock *hsk = homa_sk(sk);
	printk(KERN_NOTICE "closing socket %d\n", hsk->client_port);
	homa_sock_destroy(hsk, &homa.port_map);
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
 * homa_ioc_recv() - The top-level function for the ioctl that implements
 * the homa_recv user-level API.
 * @sk:       Socket for this request.
 * @arg:      Used to pass information from/to user space.
 *
 * Return: 0 on success, otherwise a negative errno.
 */
int homa_ioc_recv(struct sock *sk, unsigned long arg) {
	struct homa_sock *hsk = homa_sk(sk);
	struct homa_args_recv_ipv4 args;
	struct iovec iov;
	struct iov_iter iter;
	int err;
	struct homa_message_in *msgin;
	struct homa_addr *source;
	long timeo;
	int noblock = 0;
	int result;
	struct homa_client_rpc *crpc = NULL;

	if (unlikely(copy_from_user(&args, (void *) arg,
			offsetof(struct homa_args_recv_ipv4, source_addr))))
		return -EFAULT;
	err = import_single_range(READ, args.buf, args.len, &iov,
		&iter);
	if (unlikely(err))
		return err;

	lock_sock(sk);
	while (1) {
		if (!list_empty(&hsk->ready_server_rpcs)) {
			struct homa_server_rpc *srpc;
			srpc = list_first_entry(&hsk->ready_server_rpcs,
				struct homa_server_rpc, ready_links);
			list_del(&srpc->ready_links);
			srpc->state = SRPC_IN_SERVICE;
			msgin = &srpc->request;
			source = &srpc->client;
			args.id = srpc->id;
			break;
		}
		if (!list_empty(&hsk->ready_client_rpcs)) {
			crpc = list_first_entry(&hsk->ready_client_rpcs,
				struct homa_client_rpc, ready_links);
			msgin = &crpc->response;
			source = &crpc->dest;
			args.id = crpc->id;
			break;
		}
		if (noblock) {
			err = -EAGAIN;
			goto error;
		}
		timeo = sock_rcvtimeo(sk, noblock);
		timeo = homa_wait_ready_msg(sk, &timeo);
		if (signal_pending(current)) {
			err = sock_intr_errno(timeo);
			goto error;
		}
	}

	args.source_addr.sin_family = AF_INET;
	args.source_addr.sin_port = htons(source->dport);
	args.source_addr.sin_addr.s_addr = source->daddr;
	memset(args.source_addr.sin_zero, 0,
			sizeof(args.source_addr.sin_zero));
	homa_message_in_copy_data(msgin, &iter, args.len);
	result = msgin->total_length;
	if (crpc) {
		homa_client_rpc_free(crpc);
	}
	homa_message_in_destroy(msgin);
	release_sock(sk);
	if (unlikely(copy_to_user(
			&((struct homa_args_recv_ipv4 *) arg)->source_addr,
			&args.source_addr, sizeof(args) -
			offsetof(struct homa_args_recv_ipv4, source_addr))))
		return -EFAULT;
	return result;
	
error:
	release_sock(sk);
	return err;
}

/**
 * homa_ioc_reply() - The top-level function for the ioctl that implements
 * the homa_reply user-level API.
 * @sk:       Socket for this request.
 * @arg:      Used to pass information from/to user space.
 *
 * Return: 0 on success, otherwise a negative errno.
 */
int homa_ioc_reply(struct sock *sk, unsigned long arg) {
	struct homa_sock *hsk = homa_sk(sk);
	struct homa_args_reply_ipv4 args;
	struct iovec iov;
	struct iov_iter iter;
	int err = 0;
	struct homa_server_rpc *srpc;

	if (unlikely(copy_from_user(&args, (void *) arg, sizeof(args))))
		return -EFAULT;
//	err = audit_sockaddr(sizeof(args.dest_addr), &args.dest_addr);
//	if (unlikely(err))
//		return err;
	err = import_single_range(WRITE, args.response, args.resplen, &iov,
		&iter);
	if (unlikely(err))
		return err;

	if (unlikely(args.dest_addr.sin_family != AF_INET))
		return -EAFNOSUPPORT;

	lock_sock(sk);
	srpc = homa_find_server_rpc(hsk, args.dest_addr.sin_addr.s_addr,
			ntohs(args.dest_addr.sin_port), args.id);
	if (!srpc || (srpc->state != SRPC_IN_SERVICE))
		goto done;
	srpc->state = SRPC_RESPONSE;

	err = homa_message_out_init(&srpc->response, sk, &iter, args.resplen,
			&srpc->client, hsk->client_port, srpc->id);
        if (unlikely(err))
		goto error;
	homa_xmit_packets(&srpc->response, sk, &srpc->client);
	if (srpc->response.next_offset >= srpc->response.length) {
		homa_server_rpc_free(srpc);
	}
done:
	release_sock(sk);
	return err;

error:
	list_del(&srpc->server_rpc_links);
	homa_server_rpc_free(srpc);
	release_sock(sk);
	return err;
}

/**
 * homa_ioc_send() - The top-level function for the ioctl that implements
 * the homa_send user-level API.
 * @sk:       Socket for this request.
 * @arg:      Used to pass information from/to user space.
 *
 * Return: 0 on success, otherwise a negative errno.
 */
int homa_ioc_send(struct sock *sk, unsigned long arg) {
	struct homa_sock *hsk = homa_sk(sk);
	struct homa_args_send_ipv4 args;
	struct iovec iov;
	struct iov_iter iter;
	int err;
	struct homa_client_rpc *crpc = NULL;

	if (unlikely(copy_from_user(&args, (void *) arg, sizeof(args))))
		return -EFAULT;
//	err = audit_sockaddr(sizeof(args.dest_addr), &args.dest_addr);
//	if (unlikely(err))
//		return err;
	err = import_single_range(WRITE, args.request, args.reqlen, &iov,
		&iter);
	if (unlikely(err))
		return err;

	if (unlikely(args.dest_addr.sin_family != AF_INET))
		return -EAFNOSUPPORT;

	lock_sock(sk);
	crpc = homa_client_rpc_new(hsk, &args.dest_addr, args.reqlen, &iter);
	if (IS_ERR(crpc)) {
		err = PTR_ERR(crpc);
		crpc = NULL;
		goto error;
	}
	
	homa_xmit_packets(&crpc->request, sk, &crpc->dest);
	if (unlikely(copy_to_user(&((struct homa_args_send_ipv4 *) arg)->id,
			&crpc->id, sizeof(crpc->id)))) {
		err = -EFAULT;
		goto error;
	}
	release_sock(sk);
	return 0;

    error:
	if (crpc)
		homa_client_rpc_free(crpc);
	release_sock(sk);
	return err;
}

/**
 * homa_ioctl() - Implements the ioctl system call for Homa sockets.
 * @sk:    Socket on which the system call was invoked.
 * @cmd:   Identifier for a particular ioctl operation.
 * @arg:   Operation-specific argument; typically the address of a block
 *         of data in user address space.
 *
 * Return: 0 on success, otherwise a negative errno.
 */
int homa_ioctl(struct sock *sk, int cmd, unsigned long arg) {
	switch (cmd) {
	case HOMAIOCSEND:
		return homa_ioc_send(sk, arg);
	case HOMAIOCRECV:
		return homa_ioc_recv(sk, arg);
	case HOMAIOCINVOKE:
		printk(KERN_NOTICE "HOMAIOCINVOKE not yet implemented\n");
		return -EINVAL;
	case HOMAIOCREPLY:
		return homa_ioc_reply(sk, arg);
	case HOMAIOCABORT:
		printk(KERN_NOTICE "HOMAIOCABORT not yet implemented\n");
		return -EINVAL;
	default:
		printk(KERN_NOTICE "Unknown Homa ioctl: %d\n", cmd);
		return -EINVAL;
	}
}

/**
 * homa_socket() - Implements the socket(2) system call for sockets.
 * @sk:    Socket on which the system call was invoked. The non-Homa
 *         parts have already been initialized.
 *
 * Return: always 0 (success).
 */
int homa_socket(struct sock *sk)
{
	struct homa_sock *hsk = homa_sk(sk);
	homa_sock_init(hsk, &homa);
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
	/* Homa doesn't support the usual read-write kernel calls; must
	 * invoke operations through ioctls in order to manipulate RPC ids.
	 */
	return -EINVAL;
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
	/* Homa doesn't support the usual read-write kernel calls; must
	 * invoke operations through ioctls in order to manipulate RPC ids.
	 */
	return -EINVAL;
}

/**
 * homa_wait_ready_msg() - Wait until there exists at least one complete
 * message that is ready for service.
 * @sk:      Homa socket on which the message will arrive.
 * @timeo:   Maximum time to wait; modified before return to hold the wait
 *           time remaining.
 * Return:   Zero or a negative errno value to return to app.
 */
int homa_wait_ready_msg(struct sock *sk, long *timeo)
{
	DEFINE_WAIT_FUNC(wait, woken_wake_function);
	int rc;

	add_wait_queue(sk_sleep(sk), &wait);
	sk_set_bit(SOCKWQ_ASYNC_WAITDATA, sk);
	rc = sk_wait_event(sk, timeo,
			!list_empty(&homa_sk(sk)->ready_server_rpcs)
			|| !list_empty(&homa_sk(sk)->ready_client_rpcs), &wait);
	sk_clear_bit(SOCKWQ_ASYNC_WAITDATA, sk);
	remove_wait_queue(sk_sleep(sk), &wait);
	return rc;
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
	__be32 saddr = ip_hdr(skb)->saddr;
	int length = skb->len;
	struct common_header *h = (struct common_header *) skb->data;
	struct homa_sock *hsk = NULL;
	__u16 dport;
	char buffer[200];

	if (length < HOMA_MAX_HEADER) {
		printk(KERN_WARNING "Homa packet from %s too short: "
				"%d bytes\n",
				homa_print_ipv4_addr(saddr, buffer), length);
		goto discard;
	}
	printk(KERN_NOTICE "incoming Homa packet: %s\n",
			homa_print_packet(skb, buffer, sizeof(buffer)));

	dport = ntohs(h->dport);
	hsk = homa_sock_find(&homa.port_map, dport);
	if (!hsk) {
		/* Eventually should return an error result to sender if
		 * it is a client.
		 */
		printk(KERN_WARNING "Homa packet from %s sent to "
			"unknown port %u\n",
			homa_print_ipv4_addr(saddr, buffer), dport);
		goto discard;
	}
	if (dport < HOMA_MIN_CLIENT_PORT) {
		/* We are the server for this RPC. */
		struct homa_server_rpc *srpc;
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
	} else {
		/* We are the client for this RPC. */
		struct homa_client_rpc *crpc;
		crpc = homa_find_client_rpc(hsk, ntohs(h->sport), h->id);
		if (!crpc)
			goto discard;
		switch (h->type) {
		case DATA:
			homa_data_from_server(&homa, skb, hsk, crpc);
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