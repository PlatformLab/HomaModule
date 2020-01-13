/* Copyright (c) 2019, Stanford University
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

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

/* Global data for Homa. Never reference homa_data directory. Always use
 * the homa variable instead; this allows overriding during unit tests.
 */
struct homa homa_data;
struct homa *homa = &homa_data;

/* True means that the Homa module is in the process of unloading itself,
 * so everyone should clean up.
 */
static bool exiting = false;

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
	.shutdown	   = homa_shutdown,
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
	.backlog_rcv       = homa_backlog_rcv,
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

/* Top-level structure describing the Homa protocol. */
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
	.handler =	homa_pkt_recv,
	.err_handler =	homa_err_handler,
	.no_policy =	1,
	.netns_ok =	1,
};

/* Describes file operations implemented for /proc/net/homa_metrics. */
static const struct file_operations homa_metrics_fops = {
	.open		= homa_metrics_open,
	.read		= homa_metrics_read,
	.release	= homa_metrics_release,
};

/* Used to remove /proc/net/homa_metrics when the module is unloaded. */
static struct proc_dir_entry *metrics_dir_entry = NULL;

/* Used to configure sysctl access to Homa configuration parameters.*/
static struct ctl_table homa_ctl_table[] = {
	{
		.procname	= "abort_resends",
		.data		= &homa_data.abort_resends,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
	},
	{
		.procname	= "cutoff_version",
		.data		= &homa_data.cutoff_version,
		.maxlen		= sizeof(int),
		.mode		= 0444,
		.proc_handler	= proc_dointvec
	},
	{
		.procname	= "flags",
		.data		= &homa_data.flags,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
	},
	{
		.procname	= "grant_increment",
		.data		= &homa_data.grant_increment,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= homa_dointvec
	},
	{
		.procname	= "link_mbps",
		.data		= &homa_data.link_mbps,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= homa_dointvec
	},
	{
		.procname	= "max_dead_buffs",
		.data		= &homa_data.max_dead_buffs,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
	},
	{
		.procname	= "max_prio",
		.data		= &homa_data.max_prio,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= homa_dointvec
	},
	{
		.procname	= "max_gro_skbs",
		.data		= &homa_data.max_gro_skbs,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= homa_dointvec
	},
	{
		.procname	= "max_gso_size",
		.data		= &homa_data.max_gso_size,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= homa_dointvec
	},
	{
		.procname	= "max_nic_queue_ns",
		.data		= &homa_data.max_nic_queue_ns,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= homa_dointvec
	},
	{
		.procname	= "max_sched_prio",
		.data		= &homa_data.max_sched_prio,
		.maxlen		= sizeof(int),
		.mode		= 0444,
		.proc_handler	= proc_dointvec
	},
	{
		.procname	= "min_prio",
		.data		= &homa_data.min_prio,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= homa_dointvec
	},
	{
		.procname	= "reap_limit",
		.data		= &homa_data.reap_limit,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
	},
	{
		.procname	= "resend_interval",
		.data		= &homa_data.resend_interval,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
	},
	{
		.procname	= "resend_ticks",
		.data		= &homa_data.resend_ticks,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
	},
	{
		.procname	= "rtt_bytes",
		.data		= &homa_data.rtt_bytes,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= homa_dointvec
	},
	{
		.procname	= "temp",
		.data		= homa_data.temp,
		.maxlen		= sizeof(homa_data.temp),
		.mode		= 0644,
		.proc_handler	= homa_dointvec
	},
	{
		.procname	= "throttle_min_bytes",
		.data		= &homa_data.throttle_min_bytes,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
	},
	{
		.procname	= "unsched_cutoffs",
		.data		= &homa_data.unsched_cutoffs,
		.maxlen		= HOMA_NUM_PRIORITIES*sizeof(int),
		.mode		= 0644,
		.proc_handler	= homa_dointvec
	},
	{
		.procname	= "verbose",
		.data		= &homa_data.verbose,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= homa_dointvec
	},
	{}
};

/* Used to remove sysctl values when the module is unloaded. */
static struct ctl_table_header *homa_ctl_header;

/* Tasklet that does all of the real work for timers. Runs at SOFTIRQ level. */
static struct tasklet_struct timer_tasklet;

/* IRQ-level timer that triggers timer-based operations such as resends
 * and aborts. Used only to schedule timer_tasklet. */
static struct hrtimer hrtimer;

/* Time between consecutive firings of hrtimer. */
static ktime_t tick_interval;

/**
 * homa_load() - invoked when this module is loaded into the Linux kernel
 * Return: 0 on success, otherwise a negative errno.
 */
static int __init homa_load(void) {
	int status;
	struct timespec ts;
	
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
		printk(KERN_ERR "inet_add_protocol failed in homa_load: %d\n",
		    status);
		goto out_cleanup;
	}

	status = homa_init(homa);
	if (status)
		goto out_cleanup;
	metrics_dir_entry = proc_create("homa_metrics", S_IRUGO,
			init_net.proc_net, &homa_metrics_fops);
	if (!metrics_dir_entry) {
		printk(KERN_ERR "couldn't create /proc/net/homa_metrics\n");
		status = -ENOMEM;
		goto out_cleanup;
	}

	homa_ctl_header = register_net_sysctl(&init_net, "net/homa",
			homa_ctl_table);
	if (!homa_ctl_header) {
		printk(KERN_ERR "couldn't register Homa sysctl parameters\n");
		status = -ENOMEM;
		goto out_cleanup;
	}
	
	status = homa_offload_init();
	if (status != 0) {
		printk(KERN_ERR "Homa couldn't init offloads\n");
		goto out_cleanup;
	}
	tasklet_init(&timer_tasklet, homa_tasklet_handler, 0);
	hrtimer_init(&hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	hrtimer.function = &homa_hrtimer;
	ts.tv_nsec = 1000000;                   /* 1 ms */
	ts.tv_sec = 0;
	tick_interval = timespec_to_ktime(ts);
	hrtimer_start(&hrtimer, tick_interval, HRTIMER_MODE_REL);
	
	tt_init("timetrace");
	
	return 0;

out_cleanup:
	unregister_net_sysctl_table(homa_ctl_header);
	proc_remove(metrics_dir_entry);
	homa_destroy(homa);
	inet_del_protocol(&homa_protocol, IPPROTO_HOMA);
	inet_unregister_protosw(&homa_protosw);
	proto_unregister(&homa_prot);
out:
	return status;
}

/**
 * homa_unload() - invoked when this module is unloaded from the Linux kernel.
 */
static void __exit homa_unload(void) {
	printk(KERN_NOTICE "Homa module unloading\n");
	exiting = true;
	
	tt_destroy();
	
	/* Stopping the hrtimer and tasklet is tricky, because each
	 * reschedules the other. This means that the timer could get
	 * invoked again after executing tasklet_disable. So, we stop
	 * it yet again. The exiting variable will cause it to do
	 * nothing, in case it triggers again before we cancel it the
	 * second time. Very tricky! 
	 */
	hrtimer_cancel(&hrtimer);
	tasklet_kill(&timer_tasklet);
	hrtimer_cancel(&hrtimer);
	if (homa_offload_end() != 0)
		printk(KERN_ERR "Homa couldn't stop offloads\n");
	unregister_net_sysctl_table(homa_ctl_header);
	proc_remove(metrics_dir_entry);
	homa_destroy(homa);
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
 * @addr:    Contains the desired port number.
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
	return homa_sock_bind(&homa->port_map, hsk, ntohs(addr_in->sin_port));
}

/**
 * homa_close() - Invoked when close system call is invoked on a Homa socket.
 * @sk:      Socket being closed
 * @timeout: ??
 */
void homa_close(struct sock *sk, long timeout) {
	struct homa_sock *hsk = homa_sk(sk);
	printk(KERN_NOTICE "closing socket %d\n", hsk->client_port);
	homa_sock_destroy(hsk);
	sk_common_release(sk);
	tt_record2("closed socket, client port %d, server port %d\n",
			hsk->client_port, hsk->server_port);
	tt_freeze();
}

/**
 * homa_shutdown() - Implements the shutdown system call for Homa sockets.
 * @sk:      Socket to shut down.
 * @how:     Ignored: for other sockets, can independently shut down
 *           sending and receiving, but for Homa any shutdown will
 *           shut down everything.
 *
 * Return: 0 on success, otherwise a negative errno.
 */
int homa_shutdown(struct socket *sock, int how)
{
	lock_sock(sock->sk);
	homa_sock_shutdown(homa_sk(sock->sk));
	release_sock(sock->sk);
	return 0;
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
	int result;
	struct homa_rpc *rpc = NULL;

	tt_record1("homa_ioc_recv starting, port %d",
			hsk->server_port != 0 ? hsk->server_port : 
			hsk->client_port);
	if (unlikely(copy_from_user(&args, (void *) arg,
			sizeof(args))))
		return -EFAULT;
	err = import_single_range(READ, args.buf, args.len, &iov,
		&iter);		
	if (unlikely(err))
		return err;
	rpc = homa_wait_for_message(hsk, args.flags, args.id);
	if (IS_ERR(rpc)) {
		err = PTR_ERR(rpc);
		rpc = NULL;
		goto error;
	}
	
	/* Must free the RPC lock before copying to user space (see
	 * sync.txt). Mark the RPC so we can still access the RPC
	 * even without holding its lock.
	 */
	rpc->dont_reap = true;
	if (rpc->is_client)
		homa_rpc_free(rpc);
	else
		rpc->state = RPC_IN_SERVICE;
	homa_rpc_unlock(rpc);
	
	args.id = rpc->id;
	args.source_addr.sin_family = AF_INET;
	args.source_addr.sin_port = htons(rpc->dport);
	args.source_addr.sin_addr.s_addr = rpc->peer->addr;
	memset(args.source_addr.sin_zero, 0,
			sizeof(args.source_addr.sin_zero));
	if (unlikely(copy_to_user(
			&((struct homa_args_recv_ipv4 *) arg)->source_addr,
			&args.source_addr, sizeof(args) -
			offsetof(struct homa_args_recv_ipv4, source_addr)))) {
		err = -EFAULT;
		printk(KERN_NOTICE "homa_ioc_recv couldn't copy back args");
		goto error;
	}
	
	if (rpc->error) {
		err = rpc->error;
		goto error;
	}
	
//	tt_record1("starting copy_data, %d bytes in message",
//			rpc->msgin.total_length);
	result = homa_message_in_copy_data(&rpc->msgin, &iter, args.len);
//	tt_record1("finished copy_data, copied %d bytes", result);
	tt_record2("homa_ioc_recv finished, id %u, port %d",
			rpc->id & 0xffffffff,
			rpc->is_client ? hsk->client_port : hsk->server_port);
	rpc->dont_reap = false;
	return result;
	
error:
	tt_record1("homa_ioc_recv error %d", err);
	if (rpc != NULL) {
		rpc->dont_reap = false;
	}
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
	int err = 0;
	struct homa_rpc *srpc;
	struct homa_peer *peer;
	struct sk_buff *skbs;

	if (unlikely(copy_from_user(&args, (void *) arg, sizeof(args))))
		return -EFAULT;
	tt_record2("homa_ioc_reply starting, id %llu, port %d",
			args.id, hsk->server_port);
//	err = audit_sockaddr(sizeof(args.dest_addr), &args.dest_addr);
//	if (unlikely(err))
//		return err;
	if (unlikely(args.dest_addr.sin_family != AF_INET))
		return -EAFNOSUPPORT;
	peer = homa_peer_find(&hsk->homa->peers, args.dest_addr.sin_addr.s_addr,
			&hsk->inet);
	if (IS_ERR(peer))
		return PTR_ERR(peer);
	skbs = homa_fill_packets(hsk->homa, peer, args.response, args.resplen);
	if (IS_ERR(skbs))
		return PTR_ERR(skbs);
	
	srpc = homa_find_server_rpc(hsk, args.dest_addr.sin_addr.s_addr,
			ntohs(args.dest_addr.sin_port), args.id);
	if (!srpc) {
		homa_free_skbs(skbs);
		return -EINVAL;
	}
	if (srpc->state != RPC_IN_SERVICE) {
		homa_rpc_free(srpc);
		err = -EINVAL;
		goto done;
	}
	srpc->state = RPC_OUTGOING;

	homa_message_out_init(srpc, hsk->server_port, skbs, args.resplen);
	homa_xmit_data(srpc, false);
	if (!srpc->msgout.next_packet) {
		homa_rpc_free(srpc);
	}
done:
	homa_rpc_unlock(srpc);
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
	int err;
	struct homa_rpc *crpc;
			
	if (unlikely(copy_from_user(&args, (void *) arg, sizeof(args))))
		return -EFAULT;
//	err = audit_sockaddr(sizeof(args.dest_addr), &args.dest_addr);
//	if (unlikely(err))
//		return err;
	tt_record4("homa_ioc_send starting, target 0x%x:%d, port %d, id %u",
			ntohl(args.dest_addr.sin_addr.s_addr),
			ntohs(args.dest_addr.sin_port),
			hsk->client_port, atomic64_read(&hsk->next_outgoing_id));
	if (unlikely(args.dest_addr.sin_family != AF_INET))
		return -EAFNOSUPPORT;
	
	crpc = homa_rpc_new_client(hsk, &args.dest_addr, args.request,
			args.reqlen);
	if (IS_ERR(crpc)) {
		err = PTR_ERR(crpc);
		crpc = NULL;
		goto error;
	}
	homa_xmit_data(crpc, false);

	if (unlikely(copy_to_user(&((struct homa_args_send_ipv4 *) arg)->id,
			&crpc->id, sizeof(crpc->id)))) {
		err = -EFAULT;
		goto error;
	}
	homa_rpc_unlock(crpc);
	return 0;

    error:
	if (crpc) {
		homa_rpc_free(crpc);
		homa_rpc_unlock(crpc);
	}
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
	int result;
	switch (cmd) {
	case HOMAIOCSEND:
		result = homa_ioc_send(sk, arg);
		break;
	case HOMAIOCRECV:
		result = homa_ioc_recv(sk, arg);
		break;
	case HOMAIOCINVOKE:
		printk(KERN_NOTICE "HOMAIOCINVOKE not yet implemented\n");
		result = -EINVAL;
		break;
	case HOMAIOCREPLY:
		result = homa_ioc_reply(sk, arg);
		break;
	case HOMAIOCABORT:
		printk(KERN_NOTICE "HOMAIOCABORT not yet implemented\n");
		result = -EINVAL;
		break;
	default:
		printk(KERN_NOTICE "Unknown Homa ioctl: %d\n", cmd);
		result = -EINVAL;
		break;
	}
	return result;
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
	homa_sock_init(hsk, homa);
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
 * @sk:    Socket for the operation
 */
void homa_unhash(struct sock *sk) {
	printk(KERN_WARNING "unimplemented unhash invoked on Homa socket\n");
}

/**
 * homa_rehash() - ??.
 * @sk:    Socket for the operation
 */
void homa_rehash(struct sock *sk) {
	printk(KERN_WARNING "unimplemented rehash invoked on Homa socket\n");
}

/**
 * homa_get_port() - ??.
 * @sk:    Socket for the operation
 * @snum:  ??
 * Return: ??
 */
int homa_get_port(struct sock *sk, unsigned short snum) {
	printk(KERN_WARNING "unimplemented get_port invoked on Homa socket\n");
	return 0;
}

/**
 * homa_diag_destroy() - ??.
 * @sk:    Socket for the operation
 * @err:   ??
 * Return: ??
 */
int homa_diag_destroy(struct sock *sk, int err) {
	printk(KERN_WARNING "unimplemented diag_destroy invoked on Homa socket\n");
	return -ENOSYS;

}

/**
 * homa_v4_early_demux() - Invoked by IP for ??.
 * @skb:    Socket buffer.
 * Return: Always 0?
 */
int homa_v4_early_demux(struct sk_buff *skb) {
	printk(KERN_WARNING "unimplemented early_demux invoked on Homa socket\n");
	return 0;
}

/**
 * homa_v4_early_demux_handler() - invoked by IP for ??.
 * @skb:    Socket buffer.
 * @return: Always 0?
 */
int homa_v4_early_demux_handler(struct sk_buff *skb) {
	printk(KERN_WARNING "unimplemented early_demux_handler invoked on Homa socket\n");
	return 0;
}

/**
 * homa_handler() - Top-level input packet handler; invoked by IP through
 * homa_protocol.handler when a Homa packet arrives.
 * @skb:   The incoming packet.
 * Return: Always 0
 */
int homa_pkt_recv(struct sk_buff *skb) {
	__be32 saddr;
	struct common_header *h;
	struct sk_buff *others;
	__u16 dport;
	static __u64 last = 0;
	__u64 now;
	int header_offset;
	int first_packet = 1;
	struct homa_sock *hsk;
	
	INC_METRIC(pkt_recv_calls, 1);
	now = get_cycles();
	if ((now - last) > 1000000) {
		int scaled_ms = (int) (10*(now-last)/cpu_khz);
		if ((scaled_ms >= 50) && (scaled_ms < 10000)) {
			tt_record3("Gap in incoming packets: %d cycles "
					"(%d.%1d ms)",
					(int) (now - last), scaled_ms/10,
					scaled_ms%10);
			printk(KERN_NOTICE "Gap in incoming packets: %llu "
					"cycles, (%d.%1d ms)", (now - last),
					scaled_ms/10, scaled_ms%10);
		}
	}
	last = now;
	
	/* skb may actually contain many distinct packets, linked through
	 * skb_shinfo(skb)->frag_list by the Homa GRO mechanism. Each
	 * iteration through this loop processes one of those packets.
	 */
	others = skb_shinfo(skb)->frag_list;
	skb_shinfo(skb)->frag_list = NULL;
	while (1) {
		saddr = ip_hdr(skb)->saddr;
		
		/* Make sure the header is available at skb->data. One
		 * complication: it's possible that the IP header hasn't
		 * yet been removed (this happens for GRO packets on
		 * the frag_list, since they aren't handled explicitly
		 * by IP.
		 */
		header_offset = skb_transport_header(skb) - skb->data;
		if (skb->len < (HOMA_MAX_HEADER + header_offset)) {
			if (homa->verbose)
				printk(KERN_WARNING "Homa packet from %s too "
						"short: %d bytes\n",
						homa_print_ipv4_addr(saddr),
						skb->len - header_offset);
			INC_METRIC(short_packets, 1);
			goto discard;
		}
	
		/* The code below makes the header available at skb->data, even
		 * if the packet is fragmented.
		 */
		if (!pskb_may_pull(skb, HOMA_MAX_HEADER + header_offset)) {
			if (homa->verbose)
				printk(KERN_NOTICE "Homa can't handle fragmented "
						"packet (no space for header); "
						"discarding\n");
			UNIT_LOG("", "pskb discard");
			goto discard;
		}
		if (header_offset)
			__skb_pull(skb, header_offset);
		
		h = (struct common_header *) skb->data;
		if (first_packet) {
			tt_record4("homa_pkt_recv: first packet from 0x%x:%d, "
					"id %llu, type %d",
					ntohl(saddr), ntohs(h->sport),
					h->id, h->type);
			first_packet = 0;
		}
		if (unlikely(h->type == FREEZE)) {
			/* Check for FREEZE here, rather than in homa_incoming.c,
			 * so it will work even if the RPC and/or socket are
			 * unknown.
			 */
			tt_record4("Received freeze request on port %d from "
					"0x%x:%d, id %d",
					ntohs(h->dport), ntohl(saddr),
					ntohs(h->sport), h->id);
			tt_freeze();
			goto discard;
		}
		
		/* Find the socket and existing RPC (if there is one) for this
		 * packet, and lock the RPC.
		 */
		dport = ntohs(h->dport);
		hsk = homa_sock_find(&homa->port_map, dport);
		if (!hsk) {
			/* Eventually should return an error result to sender if
			 * it is a client.
			 */
			if (homa->verbose)
				printk(KERN_NOTICE "Homa packet from %s "
					"referred to unknown port %u\n",
					homa_print_ipv4_addr(saddr), dport);
			goto discard;
		}
		
		homa_pkt_dispatch(skb, hsk);
		goto next_packet;
		
discard:
		kfree_skb(skb);
		
next_packet:
		if (others == NULL)
			break;
		skb = others;
		others = others->next;
	}
	
	check_pacer(homa, 1);
	return 0;
}

/**
 * homa_backlog_rcv() - Invoked to handle packets saved on a socket's
 * backlog because it was locked when the packets first arrived.
 * @sk:     Homa socket that owns the packet's destination port.
 * @skb:    The incoming packet. This function takes ownership of the packet
 *          (we'll delete it).
 *
 * Return:  Always returns 0.
 */
int homa_backlog_rcv(struct sock *sk, struct sk_buff *skb)
{
	printk(KERN_WARNING "unimplemented backlog_rcv invoked on Homa socket\n");
	kfree_skb(skb);
	return 0;
}

/**
 * homa_err_handler() - Invoked by IP to handle an incoming error
 * packet, such as ICMP UNREACHABLE.
 * @skb:   The incoming packet.
 * @info:  Information about the error that occurred?
 */
void homa_err_handler(struct sk_buff *skb, u32 info) {
	const struct iphdr *iph = (const struct iphdr *)skb->data;
	int type = icmp_hdr(skb)->type;
	int code = icmp_hdr(skb)->code;
	
	if (type == ICMP_DEST_UNREACH) {
		int error;
		if (code == ICMP_PROT_UNREACH)
			error = -EPROTONOSUPPORT;
		else
			error = -EHOSTUNREACH;
		tt_record2("ICMP destination unreachable: 0x%x (daddr 0x%x)",
				ntohl(iph->saddr), ntohl(iph->daddr));
		homa_peer_abort(homa, iph->daddr, error);
	} else {
		if (homa->verbose)
			printk(KERN_NOTICE "homa_err_handler invoked with "
				"info %x, ICMP type %d, ICMP code %d\n",
				info, type, code);
	}
}

/**
 * homa_poll() - Invoked by Linux as part of implementing select, poll,
 * epoll, etc.
 * @file:  Open file that is participating in a poll, select, etc.
 * @sock:  A Homa socket, associated with @file.
 * @wait:  This table will be registered with the socket, so that it
 *         is notified when the socket's ready state changes.
 * 
 * Return: A mask of bits such as EPOLLIN, which indicate the current
 *         state of the socket.
 */
__poll_t homa_poll(struct file *file, struct socket *sock,
	       struct poll_table_struct *wait) {
	struct sock *sk = sock->sk;
	__poll_t mask;
	
	/* It seems to be standard practice for poll functions *not* to
	 * acquire the socket lock, so we don't do it here; not sure
	 * why...
	 */
	
	sock_poll_wait(file, sk_sleep(sk), wait);
	mask = POLLOUT | POLLWRNORM;
	
	if (!list_empty(&homa_sk(sk)->ready_requests) ||
			!list_empty(&homa_sk(sk)->ready_responses))
		mask |= POLLIN | POLLRDNORM;
	return mask;
}

/**
 * homa_metrics_open() - This function is invoked when /proc/net/homa_metrics is
 * opened.
 * @inode:    The inode corresponding to the file.
 * @file:     Information about the open file.
 * 
 * Return: always 0.
 */
int homa_metrics_open(struct inode *inode, struct file *file)
{
	/* Collect all of the metrics when the file is opened, and save
	 * these for use by subsequent reads (don't want the metrics to
	 * change between reads). If there are concurrent opens on the
	 * file, only read the metrics once, during the first open, and
	 * use this copy for subsequent opens, until the file has been
	 * completely closed.
	 */
	spin_lock(&homa->metrics_lock);
	if (homa->metrics_active_opens == 0) {
		homa_print_metrics(homa);
	}
	homa->metrics_active_opens++;
	spin_unlock(&homa->metrics_lock);
	return 0;
}

/**
 * homa_metrics_read() - This function is invoked to handle read kernel calls on
 * /proc/net/homa_metrics.
 * @file:    Information about the file being read.
 * @buffer:  Address in user space of the buffer in which data from the file
 *           should be returned.
 * @length:  Number of bytes available at @buffer.
 * @offset:  Current read offset within the file.
 *
 * Return: the number of bytes returned at @buffer. 0 means the end of the
 * file was reached, and a negative number indicates an error (-errno).
 */
ssize_t homa_metrics_read(struct file *file, char __user *buffer,
		size_t length, loff_t *offset)
{
	size_t copied;
	
	if (*offset >= homa->metrics_length)
		return 0;
	copied = homa->metrics_length - *offset;
	if (copied > length)
		copied = length;
	if (copy_to_user(buffer, homa->metrics + *offset, copied))
		return -EFAULT;
	*offset += copied;
	return copied;
}

/**
 * homa_metrics_release() - This function is invoked when the last reference to
 * an open /proc/net/homa_metrics is closed.  It performs cleanup.
 * @inode:    The inode corresponding to the file.
 * @file:     Information about the open file.
 * 
 * Return: always 0. 
 */
int homa_metrics_release(struct inode *inode, struct file *file)
{
	spin_lock(&homa->metrics_lock);
	homa->metrics_active_opens--;
	spin_unlock(&homa->metrics_lock);
	return 0;
}

/**
 * homa_dointvec() - This function is a wrapper around proc_dointvec. It is
 * invoked to read and write sysctl values and also update other values
 * that depend on the modified value.
 * @table:    sysctl table describing value to be read or written.
 * @write:    Nonzero means value is being written, 0 means read.
 * @buffer:   Address in user space of the input/output data.
 * @lenp:     Not exactly sure.
 * @ppos:     Not exactly sure.
 * 
 * Return: 0 for success, nonzero for error. 
 */
int homa_dointvec(struct ctl_table *table, int write,
		void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int result;
	result = proc_dointvec(table, write, buffer, lenp, ppos);
	if (write) {
		/* Don't worry which particular value changed; update
		 * all info that is dependent on any sysctl value.
		 */
		homa_outgoing_sysctl_changed(homa);
		
		/* For this value, only call the method when this
		 * particular value was written (don't want to increment
		 * cutoff_version otherwise).
		 */
		if (table->data == &homa_data.unsched_cutoffs) {
			homa_prios_changed(homa);
		}
	}
	return result;
}

/**
 * homa_hrtimer() - This function is invoked at regular intervals by the
 * hrtimer mechanism. Runs at IRQ level.
 * @timer:   The timer that triggered; not used.
 * 
 * Return:   Always HRTIMER_RESTART.
 */
enum hrtimer_restart homa_hrtimer(struct hrtimer *timer)
{
	if (exiting) {
		return HRTIMER_NORESTART;
	}
	tasklet_hi_schedule(&timer_tasklet);
	
	/* Don't restart here; homa_tasklet_handler will restart the timer
	 * after it finishes its work (this guarantees a minimum interval
	 * between invocations, even if the work takes a long time).*/
	return HRTIMER_NORESTART;
}

/**
 * homa_tasklet_handler() - Invoked at SOFTIRQ level to handle timing-
 * related functions for Homa.
 * @data:   Not used.
 */
void homa_tasklet_handler(unsigned long data)
{
	homa_timer(homa);
	hrtimer_start(&hrtimer, tick_interval, HRTIMER_MODE_REL);
}
