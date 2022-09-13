/* Copyright (c) 2019-2022 Stanford University
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
#include "homa_lcache.h"

#ifndef __UNIT_TEST__
MODULE_LICENSE("Dual MIT/GPL");
#endif
MODULE_AUTHOR("John Ousterhout");
MODULE_DESCRIPTION("Homa transport protocol");
MODULE_VERSION("0.01");

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

/* Thread that runs timer code to detect lost packets and crashed peers. */
static struct task_struct *timer_kthread;

/* Set via sysctl to request that information on a particular topic
 * be printed to the system log. The value written determines the
 * topic.
 */
static int log_topic;

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
	.handler =	homa_softirq,
	.err_handler =	homa_err_handler,
	.no_policy =	1,
};

/* Describes file operations implemented for /proc/net/homa_metrics. */
static const struct proc_ops homa_metrics_pops = {
	.proc_open         = homa_metrics_open,
	.proc_read         = homa_metrics_read,
	.proc_lseek        = homa_metrics_lseek,
	.proc_release      = homa_metrics_release,
};

/* Used to remove /proc/net/homa_metrics when the module is unloaded. */
static struct proc_dir_entry *metrics_dir_entry = NULL;

/* Used to configure sysctl access to Homa configuration parameters.*/
static struct ctl_table homa_ctl_table[] = {
	{
		.procname	= "cutoff_version",
		.data		= &homa_data.cutoff_version,
		.maxlen		= sizeof(int),
		.mode		= 0444,
		.proc_handler	= proc_dointvec
	},
	{
		.procname	= "dead_buffs_limit",
		.data		= &homa_data.dead_buffs_limit,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
	},
	{
		.procname	= "duty_cycle",
		.data		= &homa_data.duty_cycle,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= homa_dointvec
	},
	{
		.procname	= "flags",
		.data		= &homa_data.flags,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
	},
	{
		.procname	= "freeze_type",
		.data		= &homa_data.freeze_type,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
	},
	{
		.procname	= "grant_fifo_fraction",
		.data		= &homa_data.grant_fifo_fraction,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= homa_dointvec
	},
	{
		.procname	= "fifo_grant_increment",
		.data		= &homa_data.fifo_grant_increment,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= homa_dointvec
	},
	{
		.procname	= "gro_busy_us",
		.data		= &homa_data.gro_busy_usecs,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= homa_dointvec
	},
	{
		.procname	= "gro_policy",
		.data		= &homa_data.gro_policy,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
	},
	{
		.procname	= "link_mbps",
		.data		= &homa_data.link_mbps,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= homa_dointvec
	},
	{
		.procname	= "log_topic",
		.data		= &log_topic,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= homa_dointvec
	},
	{
		.procname	= "pacer_fifo_fraction",
		.data		= &homa_data.pacer_fifo_fraction,
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
		.procname	= "max_grant_window",
		.data		= &homa_data.max_grant_window,
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
		.procname	= "max_overcommit",
		.data		= &homa_data.max_overcommit,
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
		.procname	= "num_priorities",
		.data		= &homa_data.num_priorities,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= homa_dointvec
	},
	{
		.procname	= "poll_usecs",
		.data		= &homa_data.poll_usecs,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= homa_dointvec
	},
	{
		.procname	= "priority_map",
		.data		= &homa_data.priority_map,
		.maxlen		= HOMA_MAX_PRIORITIES*sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
	},
	{
		.procname	= "reap_limit",
		.data		= &homa_data.reap_limit,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
	},
	{
		.procname	= "request_ack_ticks",
		.data		= &homa_data.request_ack_ticks,
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
		.procname	= "sync_freeze",
		.data		= &homa_data.sync_freeze,
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
		.procname	= "timeout_resends",
		.data		= &homa_data.timeout_resends,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
	},
	{
		.procname	= "unsched_cutoffs",
		.data		= &homa_data.unsched_cutoffs,
		.maxlen		= HOMA_MAX_PRIORITIES*sizeof(int),
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

/* Sizes of the headers for each Homa packet type, in bytes. */
static __u16 header_lengths[] = {
	sizeof32(struct data_header),
	sizeof32(struct grant_header),
	sizeof32(struct resend_header),
	sizeof32(struct unknown_header),
	sizeof32(struct busy_header),
	sizeof32(struct cutoffs_header),
	sizeof32(struct freeze_header),
	sizeof32(struct need_ack_header),
	sizeof32(struct ack_header)
};

/* Used to remove sysctl values when the module is unloaded. */
static struct ctl_table_header *homa_ctl_header;

static DECLARE_COMPLETION(timer_thread_done);

/**
 * homa_load() - invoked when this module is loaded into the Linux kernel
 * Return: 0 on success, otherwise a negative errno.
 */
static int __init homa_load(void) {
	int status;

	printk(KERN_NOTICE "Homa module loading\n");
	printk(KERN_NOTICE "Homa structure sizes: data_header %u, "
			"data_segment %u, ack %u, "
			"grant_header %u, peer %u, ip_hdr %u, flowi %u "
			"tcp_sock %u homa_rpc %u\n",
			sizeof32(struct data_header),
			sizeof32(struct data_segment),
			sizeof32(struct homa_ack),
			sizeof32(struct grant_header),
			sizeof32(struct homa_peer),
			sizeof32(struct iphdr),
			sizeof32(struct flowi),
			sizeof32(struct tcp_sock),
			sizeof32(struct homa_rpc));
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
			init_net.proc_net, &homa_metrics_pops);
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

	timer_kthread = kthread_run(homa_timer_main, homa, "homa_timer");
	if (IS_ERR(timer_kthread)) {
		status = PTR_ERR(timer_kthread);
		printk(KERN_ERR "couldn't create homa pacer thread: error %d\n",
				status);
		timer_kthread = NULL;
		goto out_cleanup;
	}

	tt_init("timetrace", homa->temp);

	return 0;

out_cleanup:
	homa_offload_end();
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

	if (timer_kthread)
		wake_up_process(timer_kthread);
	if (homa_offload_end() != 0)
		printk(KERN_ERR "Homa couldn't stop offloads\n");
	wait_for_completion(&timer_thread_done);
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
	printk(KERN_NOTICE "closing socket %d\n", hsk->port);
	homa_sock_destroy(hsk);
	sk_common_release(sk);
	tt_record1("closed socket, port %d\n", hsk->port);
	if (hsk->homa->freeze_type == SOCKET_CLOSE)
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
	struct iovec iovstack[UIO_FASTIOV];

	// Must be freed at the end of this function.
	struct iovec *iov = NULL;
	struct iov_iter iter;
	int err;
	int result;
	struct homa_rpc *rpc = NULL;

	if (unlikely(copy_from_user(&args, (void *) arg, sizeof(args))))
		return -EFAULT;
	tt_record3("homa_ioc_recv starting, port %d, pid %d, flags %d",
			hsk->port, current->pid, args.flags);
	if (args.buf != NULL) {
		err = import_single_range(READ, args.buf, args.len, iovstack,
				&iter);
	} else {
		iov = iovstack;
		err = import_iovec(READ, args.iovec, args.len,
			ARRAY_SIZE(iovstack), &iov, &iter);
	}
	if (unlikely(err < 0))
		goto error;
	rpc = homa_wait_for_message(hsk, args.flags, args.requestedId,
			&args.source_addr);
	if (IS_ERR(rpc)) {
		err = PTR_ERR(rpc);
		rpc = NULL;
		goto error;
	}

	/* Generate time traces on both ends for long elapsed times (used
	 * for performance debugging).
	 */
	if (rpc->hsk->homa->freeze_type == SLOW_RPC) {
		uint64_t elapsed = (get_cycles() - rpc->start_cycles)>>10;
		if ((elapsed <= hsk->homa->temp[1])
				&& (elapsed >= hsk->homa->temp[0])
				&& homa_is_client(rpc->id)
				&& (rpc->msgin.total_length < 500)) {
			tt_record4("Long RTT: kcycles %d, id %d, peer 0x%x, "
					"length %d",
					elapsed, rpc->id,
					ntohl(rpc->peer->addr),
					rpc->msgin.total_length);
			homa_freeze(rpc, SLOW_RPC, "Freezing because of long "
					"elapsed time for RPC id %d, peer 0x%x");
		}
	}
	if (rpc->hsk->homa->sync_freeze) {
		rpc->hsk->homa->sync_freeze = 0;
		if (!tt_frozen) {
			struct freeze_header freeze;
			tt_record2("Freezing timetrace because of "
					"sync_freeze, id %d, peer 0x%x",
					rpc->id, htonl(rpc->peer->addr));
			tt_freeze();
			homa_xmit_control(FREEZE, &freeze, sizeof(freeze), rpc);
		}
	}

	/* Must release the RPC lock (and potentially free the RPC) before
	 * copying to user space (see sync.txt). Mark the RPC so we can
	 * still access the RPC even without holding its lock.
	 */
	rpc->dont_reap = true;
	if (homa_is_client(rpc->id)) {
		if ((args.len >= rpc->msgin.total_length) || rpc->error
				|| !(args.flags & HOMA_RECV_PARTIAL))
			homa_rpc_free(rpc);
	} else {
		rpc->state = RPC_IN_SERVICE;
	}
	homa_rpc_unlock(rpc);

	args.len = rpc->msgin.total_length;
	args.source_addr.sin_family = AF_INET;
	args.source_addr.sin_port = htons(rpc->dport);
	args.source_addr.sin_addr.s_addr = rpc->peer->addr;
	memset(args.source_addr.sin_zero, 0,
			sizeof(args.source_addr.sin_zero));
	args.actualId = rpc->id;
	args.completion_cookie = rpc->completion_cookie;
	if (unlikely(copy_to_user((void *) arg, &args, sizeof(args)))) {
		err = -EFAULT;
		printk(KERN_NOTICE "homa_ioc_recv couldn't copy back args\n");
		goto error;
	}

	if (rpc->error) {
		err = rpc->error;
		goto error;
	}

	result = homa_message_in_copy_data(&rpc->msgin, &iter, iter.count);
	tt_record4("homa_ioc_recv finished, id %u, peer 0x%x, length %d, pid %d",
			rpc->id & 0xffffffff, ntohl(rpc->peer->addr), result,
			current->pid);
	rpc->dont_reap = false;
	kfree(iov);
	return result;

error:
	tt_record2("homa_ioc_recv error %d, id %d", err, args.actualId);
	if (rpc != NULL) {
		rpc->dont_reap = false;
	}
	kfree(iov);
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
	struct iovec iovstack[UIO_FASTIOV];

	// Must be freed at the end of this function.
	struct iovec *iov = NULL;
	struct iov_iter iter;
	int err = 0;
	struct homa_rpc *srpc;
	struct homa_peer *peer;
	struct sk_buff *skbs;
	size_t length;

	if (unlikely(copy_from_user(&args, (void *) arg, sizeof(args)))) {
		err = -EFAULT;
		goto done;
	}
	tt_record3("homa_ioc_reply starting, id %llu, port %d, pid %d",
			args.id, hsk->port, current->pid);
//	err = audit_sockaddr(sizeof(args.dest_addr), &args.dest_addr);
//	if (unlikely(err))
//		return err;
	if (unlikely(args.dest_addr.sin_family != AF_INET)) {
		err = -EAFNOSUPPORT;
		goto done;
	}

	if (args.response != NULL) {
		err = import_single_range(WRITE, args.response, args.length,
				iovstack, &iter);
	} else {
		iov = iovstack;
		err = import_iovec(WRITE, args.iovec, args.length,
			ARRAY_SIZE(iovstack), &iov, &iter);
	}
	if (err < 0)
		goto done;
	err = 0;
	length = iter.count;

	peer = homa_peer_find(&hsk->homa->peers, args.dest_addr.sin_addr.s_addr,
			&hsk->inet);
	if (IS_ERR(peer)) {
		err = PTR_ERR(peer);
		goto done;
	}
	skbs = homa_fill_packets(hsk, peer, &iter);
	if (IS_ERR(skbs)) {
		err = PTR_ERR(skbs);
		goto done;
	}

	srpc = homa_find_server_rpc(hsk, args.dest_addr.sin_addr.s_addr,
			ntohs(args.dest_addr.sin_port), args.id);
	if (!srpc) {
		homa_free_skbs(skbs);
		err = -EINVAL;
		goto done;
	}
	if (srpc->state != RPC_IN_SERVICE) {
		err = -EINVAL;
		goto unlock;
	}
	srpc->state = RPC_OUTGOING;

	homa_message_out_init(srpc, hsk->port, skbs, length);
	tt_record1("homa_ioc_reply calling homa_xmit_data for id %u",
			srpc->id);
	homa_xmit_data(srpc, false);
unlock:
	homa_rpc_unlock(srpc);

done:
//	tt_record3("homa_ioc_reply finished, id %llu, port %d, length %d",
//			args.id, hsk->client_port, args.length);
	kfree(iov);
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
	struct iovec iovstack[UIO_FASTIOV];

	// Must be freed at the end of this function.
	struct iovec *iov = NULL;
	struct iov_iter iter;
	int err;
	struct homa_rpc *crpc = NULL;

	if (unlikely(copy_from_user(&args, (void *) arg, sizeof(args)))) {
		err = -EFAULT;
		goto error;
	}
//	err = audit_sockaddr(sizeof(args.dest_addr), &args.dest_addr);
//	if (unlikely(err))
//		return err;
	tt_record3("homa_ioc_send starting, target 0x%x:%d, id %u",
			ntohl(args.dest_addr.sin_addr.s_addr),
			ntohs(args.dest_addr.sin_port),
			atomic64_read(&hsk->homa->next_outgoing_id));
	if (unlikely(args.dest_addr.sin_family != AF_INET)) {
		err = -EAFNOSUPPORT;
		goto error;
	}

	if (args.request != NULL) {
		err = import_single_range(WRITE, args.request, args.length,
				iovstack, &iter);
	} else {
		iov = iovstack;
		err = import_iovec(WRITE, args.iovec, args.length,
				ARRAY_SIZE(iovstack), &iov, &iter);
	}
	if (err < 0)
		goto error;
	err = 0;

	crpc = homa_rpc_new_client(hsk, &args.dest_addr, &iter);
	if (IS_ERR(crpc)) {
		err = PTR_ERR(crpc);
		crpc = NULL;
		goto error;
	}
	crpc->completion_cookie = args.completion_cookie;
	tt_record1("homa_ioc_send calling homa_xmit_data for id %u",
			crpc->id);
	homa_xmit_data(crpc, false);

	if (unlikely(copy_to_user(&((struct homa_args_send_ipv4 *) arg)->id,
			&crpc->id, sizeof(crpc->id)))) {
		err = -EFAULT;
		goto error;
	}
	tt_record3("homa_ioc_send finished, id %llu, port %d, length %d",
			crpc->id, hsk->port, args.length);
	homa_rpc_unlock(crpc);
	kfree(iov);
	return 0;

    error:
	if (crpc) {
		homa_rpc_free(crpc);
		homa_rpc_unlock(crpc);
	}
	kfree(iov);
	return err;
}

/**
 * homa_ioc_abort() - The top-level function for the ioctl that implements
 * the homa_abort user-level API.
 * @sk:       Socket for this request.
 * @arg:      Used to pass information from user space; for this call,
 *            it's the identifier of the RPC to abort.
 *
 * Return: 0 on success, otherwise a negative errno.
 */
int homa_ioc_abort(struct sock *sk, unsigned long arg) {
	struct homa_sock *hsk = homa_sk(sk);
	uint64_t id = (uint64_t) arg;
	struct homa_rpc *rpc;

	rpc = homa_find_client_rpc(hsk, id);
	if (rpc == NULL)
		return -EINVAL;
	homa_rpc_free(rpc);
	homa_rpc_unlock(rpc);
	return 0;
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
	__u64 start = get_cycles();
	struct homa_core *core = homa_cores[raw_smp_processor_id()];
	if (current == core->thread)
		INC_METRIC(user_cycles, start - core->syscall_end_time);

	switch (cmd) {
	case HOMAIOCSEND:
		result = homa_ioc_send(sk, arg);
		core = homa_cores[raw_smp_processor_id()];
		core->syscall_end_time = get_cycles();
		INC_METRIC(send_calls, 1);
		INC_METRIC(send_cycles, core->syscall_end_time - start);
		break;
	case HOMAIOCRECV:
		result = homa_ioc_recv(sk, arg);
		core = homa_cores[raw_smp_processor_id()];
		core->syscall_end_time = get_cycles();
		INC_METRIC(recv_calls, 1);
		INC_METRIC(recv_cycles, core->syscall_end_time - start);
		break;
	case HOMAIOCREPLY:
		result = homa_ioc_reply(sk, arg);
		core = homa_cores[raw_smp_processor_id()];
		core->syscall_end_time = get_cycles();
		INC_METRIC(reply_calls, 1);
		INC_METRIC(reply_cycles, core->syscall_end_time - start);
		break;
	case HOMAIOCABORT:
		result = homa_ioc_abort(sk, arg);
		core = homa_cores[raw_smp_processor_id()];
		core->syscall_end_time = get_cycles();
		INC_METRIC(abort_calls, 1);
		INC_METRIC(abort_cycles, core->syscall_end_time - start);
		break;
	case HOMAIOCFREEZE:
		tt_record1("Freezing timetrace because of HOMAIOCFREEZE ioctl, "
				"pid %d", current->pid);
		tt_freeze();
		result = 0;
		break;
	default:
		printk(KERN_NOTICE "Unknown Homa ioctl: %d\n", cmd);
		result = -EINVAL;
		break;
	}
	core->thread = current;
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
	printk(KERN_NOTICE "opened socket %d\n", hsk->port);
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
    sockptr_t optval, unsigned int optlen) {
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
 * homa_softirq() - This function is invoked at SoftIRQ level to handle
 * incoming packets.
 * @skb:   The incoming packet.
 * Return: Always 0
 */
int homa_softirq(struct sk_buff *skb) {
	__be32 saddr;
	struct common_header *h;
	struct sk_buff *packets, *short_packets, *next;
	struct sk_buff **prev_link, **short_link;
	__u16 dport;
	static __u64 last = 0;
	__u64 start;
	int header_offset;
	int first_packet = 1;
	struct homa_sock *hsk;
	int num_packets = 0;
	int pull_length;
	struct homa_lcache lcache;

	/* Accumulates changes to homa->incoming, to avoid repeated
	 * updates to this shared variable.
	 */
	int incoming_delta = 0;

	start = get_cycles();
	INC_METRIC(softirq_calls, 1);
	homa_cores[raw_smp_processor_id()]->last_active = start;
	homa_lcache_init(&lcache);
	if ((start - last) > 1000000) {
		int scaled_ms = (int) (10*(start-last)/cpu_khz);
		if ((scaled_ms >= 50) && (scaled_ms < 10000)) {
//			tt_record3("Gap in incoming packets: %d cycles "
//					"(%d.%1d ms)",
//					(int) (start - last), scaled_ms/10,
//					scaled_ms%10);
//			printk(KERN_NOTICE "Gap in incoming packets: %llu "
//					"cycles, (%d.%1d ms)", (start - last),
//					scaled_ms/10, scaled_ms%10);
		}
	}
	last = start;

	/* skb may actually contain many distinct packets, linked through
	 * skb_shinfo(skb)->frag_list by the Homa GRO mechanism. First, pull
	 * out all the short packets into a separate list, then splice this
	 * list into the front of the packet list, so that all the short
	 * packets will get served first.
	 */

	skb->next = skb_shinfo(skb)->frag_list;
	skb_shinfo(skb)->frag_list = NULL;
	packets = skb;
	prev_link = &packets;
	short_packets = NULL;
	short_link = &short_packets;
	for (skb = packets; skb != NULL; skb = skb->next) {
		if (skb->len < 1400) {
			*prev_link = skb->next;
			*short_link = skb;
			short_link = &skb->next;
		} else
			prev_link = &skb->next;
	}
	*short_link = packets;
	packets = short_packets;

	for (skb = packets; skb != NULL; skb = next) {
		next = skb->next;
		saddr = ip_hdr(skb)->saddr;
		num_packets++;

		/* The code below makes the header available at skb->data, even
		 * if the packet is fragmented. One complication: it's possible
		 * that the IP header hasn't yet been removed (this happens for
		 * GRO packets on the frag_list, since they aren't handled
		 * explicitly by IP.
		 */
		header_offset = skb_transport_header(skb) - skb->data;
		pull_length = HOMA_MAX_HEADER + header_offset;
		if (pull_length > skb->len)
			pull_length = skb->len;
		if (!pskb_may_pull(skb, pull_length)) {
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
		if (unlikely((skb->len < sizeof(struct common_header))
				|| (h->type < DATA)
				|| (h->type >= BOGUS)
				|| (skb->len < header_lengths[h->type-DATA]))) {
			if (homa->verbose)
				printk(KERN_WARNING
						"Homa %s packet from %s too "
						"short: %d bytes\n",
						homa_symbol_for_type(h->type),
						homa_print_ipv4_addr(saddr),
						skb->len - header_offset);
			INC_METRIC(short_packets, 1);
			goto discard;
		}

		if (first_packet) {
			tt_record4("homa_softirq: first packet from 0x%x:%d, "
					"id %llu, type %d",
					ntohl(saddr), ntohs(h->sport),
					homa_local_id(h->sender_id), h->type);
			first_packet = 0;
		}
		if (unlikely(h->type == FREEZE)) {
			/* Check for FREEZE here, rather than in homa_incoming.c,
			 * so it will work even if the RPC and/or socket are
			 * unknown.
			 */
			if (!tt_frozen) {
				tt_record4("Freezing because of request on "
						"port %d from 0x%x:%d, id %d",
						ntohs(h->dport), ntohl(saddr),
						ntohs(h->sport),
						homa_local_id(h->sender_id));
				tt_freeze();
//				homa_rpc_log_active(homa, h->id);
//				homa_log_grantable_list(homa);
//				homa_log_throttled(homa);
			}
			goto discard;
		}

		dport = ntohs(h->dport);
		hsk = homa_sock_find(&homa->port_map, dport);
		if (!hsk) {
			icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);
			tt_record3("Discarding packet for unknown port %u, "
					"id %llu, type %d", dport,
					homa_local_id(h->sender_id), h->type);
			goto discard;
		}

		homa_pkt_dispatch(skb, hsk, &lcache, &incoming_delta);
		continue;

discard:
		kfree_skb(skb);
	}

	homa_lcache_release(&lcache);
	atomic_add(incoming_delta, &homa->total_incoming);
	homa_send_grants(homa);
	atomic_dec(&homa_cores[raw_smp_processor_id()]->softirq_backlog);
	INC_METRIC(softirq_cycles, get_cycles() - start);
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
 *
 * Return: zero, or a negative errno if the error couldn't be handled here.
 */
int homa_err_handler(struct sk_buff *skb, u32 info) {
	const struct iphdr *iph = (const struct iphdr *)skb->data;
	int type = icmp_hdr(skb)->type;
	int code = icmp_hdr(skb)->code;

	if ((type == ICMP_DEST_UNREACH) && (code == ICMP_PORT_UNREACH)) {
		struct common_header *h;
		char *icmp = (char *) icmp_hdr(skb);
		iph = (struct iphdr *) (icmp + sizeof(struct icmphdr));
		h = (struct common_header *) (icmp + sizeof(struct icmphdr)
				+ iph->ihl*4);
		homa_abort_rpcs(homa, iph->daddr, htons(h->dport), -ENOTCONN);
	} else if (type == ICMP_DEST_UNREACH) {
		int error;
		if (code == ICMP_PROT_UNREACH)
			error = -EPROTONOSUPPORT;
		else
			error = -EHOSTUNREACH;
		tt_record2("ICMP destination unreachable: 0x%x (daddr 0x%x)",
				ntohl(iph->saddr), ntohl(iph->daddr));
		homa_abort_rpcs(homa, iph->daddr, 0, error);
	} else {
		if (homa->verbose)
			printk(KERN_NOTICE "homa_err_handler invoked with "
				"info %x, ICMP type %d, ICMP code %d\n",
				info, type, code);
	}
	return 0;
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

	sock_poll_wait(file, sock, wait);
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
 * homa_metrics_lseek() - This function is invoked to handle seeks on
 * /proc/net/homa_metrics. Right now seeks are ignored: the file must be
 * read sequentially.
 * @file:    Information about the file being read.
 * @offset:  Distance to seek, in bytes
 * @whence:  Starting point from which to measure the distance to seek.
 */
loff_t homa_metrics_lseek(struct file *file, loff_t offset, int whence)
{
	return 0;
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
		homa_incoming_sysctl_changed(homa);
		homa_outgoing_sysctl_changed(homa);

		/* For this value, only call the method when this
		 * particular value was written (don't want to increment
		 * cutoff_version otherwise).
		 */
		if ((table->data == &homa_data.unsched_cutoffs)
				|| (table->data == &homa_data.num_priorities)) {
			homa_prios_changed(homa);
		}

		/* Handle the special value log_topic by invoking a function
		 * to print information to the log.
		 */
		if (table->data == &log_topic) {
			if (log_topic == 1)
				homa_log_grantable_list(homa);
			else if (log_topic == 2)
				homa_rpc_log_active(homa, 0);
			else if (log_topic == 3) {
				tt_record("Freezing because of sysctl");
				tt_freeze();
			} else if (log_topic == 4)
				homa_log_throttled(homa);
			else
				homa_rpc_log_active(homa, log_topic);
			log_topic = 0;
		}
	}
	return result;
}

/**
 * homa_hrtimer() - This function is invoked by the hrtimer mechanism to
 * wake up the timer thread. Runs at IRQ level.
 * @timer:   The timer that triggered; not used.
 *
 * Return:   Always HRTIMER_RESTART.
 */
enum hrtimer_restart homa_hrtimer(struct hrtimer *timer)
{
	wake_up_process(timer_kthread);
	return HRTIMER_NORESTART;
}

/**
 * homa_timer_main() - Top-level function for the timer thread.
 * @transportInfo:  Pointer to struct homa.
 *
 * Return:         Always 0.
 */
int homa_timer_main(void *transportInfo)
{
	struct homa *homa = (struct homa *) transportInfo;
	u64 nsec;
	ktime_t tick_interval;
	struct hrtimer hrtimer;

	hrtimer_init(&hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	hrtimer.function = &homa_hrtimer;
	nsec = 1000000;                   /* 1 ms */
	tick_interval = ns_to_ktime(nsec);
	while (1) {
		set_current_state(TASK_UNINTERRUPTIBLE);
		if (!exiting) {
			hrtimer_start(&hrtimer, tick_interval, HRTIMER_MODE_REL);
			schedule();
		}
		__set_current_state(TASK_RUNNING);
		if (exiting)
			break;
		homa_timer(homa);
	}
	hrtimer_cancel(&hrtimer);
	kthread_complete_and_exit(&timer_thread_done, 0);
	return 0;
}
