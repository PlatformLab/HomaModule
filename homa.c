#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/sock.h>
#include <net/inet_common.h>

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("John Ousterhout");
MODULE_DESCRIPTION("Homa transport protocol");
MODULE_VERSION("0.01");

// Homa's protocol number within the IP protocol space (this is not an
// officially allocated slot).
#define IPPROTO_HOMA 140

// Not yet sure what these variables are for.
long sysctl_homa_mem[3] __read_mostly;
int sysctl_homa_rmem_min __read_mostly;
int sysctl_homa_wmem_min __read_mostly;
atomic_long_t homa_memory_allocated;

// Forward declarations:
extern void homa_close(struct sock *sk, long timeout);
extern int homa_diag_destroy(struct sock *sk, int err);
extern int homa_disconnect(struct sock *sk, int flags);
extern void homa_err_handler(struct sk_buff *skb, u32 info);
extern int homa_get_port(struct sock *sk, unsigned short snum);
extern int homa_getsockopt(struct sock *sk, int level, int optname,
		char __user *optval, int __user *option);
extern int homa_handler(struct sk_buff *skb);
extern int homa_hash(struct sock *sk);
extern int homa_setsockopt(struct sock *sk, int level, int optname,
		char __user *optval, unsigned int optlen);
extern int homa_init_sock(struct sock *sk);
extern int homa_ioctl(struct sock *sk, int cmd, unsigned long arg);
extern __poll_t homa_poll(struct file *file, struct socket *sock,
		struct poll_table_struct *wait);
extern int homa_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
		int noblock, int flags, int *addr_len);
extern void homa_rehash(struct sock *sk);
extern int homa_sendmsg(struct sock *sk, struct msghdr *msg, size_t len);
extern int homa_sendpage(struct sock *sk, struct page *page, int offset,
		size_t size, int flags);
extern void homa_unhash(struct sock *sk);
extern int homa_v4_early_demux(struct sk_buff *skb);
extern int homa_v4_early_demux_handler(struct sk_buff *skb);

/* Information about an open socket that uses Homa.
 */
struct homa_sock {
	// The first part of the structure consists of generic socket data.
	// This must be the first field.
	struct inet_sock inet;
	
	// Everything after here is information specific to Homa sockets.
};

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
	.bind		   = inet_bind,
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
	.init		   = homa_init_sock,
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
	printk(KERN_INFO "Homa module loading\n");
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
	printk(KERN_INFO "Homa module unloading\n");
	inet_del_protocol(&homa_protocol, IPPROTO_HOMA);
	inet_unregister_protosw(&homa_protosw);
	proto_unregister(&homa_prot);
}

module_init(homa_init);
module_exit(homa_exit);

/**
 * homa_close(): invoked when close system call is invoked on a Homa socket.
 */
void homa_close(struct sock *sk, long timeout) {
	sk_common_release(sk);
}

/**
 * homa_disconnect(): invoked when disconnect system call is invoked on a
 * Homa socket.
 * @return: 0 on success, otherwise a negative errno.
 */
int homa_disconnect(struct sock *sk, int flags) {
	printk(KERN_WARNING "unimplemented disconnect invoked on Homa socket\n");
	return -ENOSYS;
}

/**
 * homa_ioctl(): implements the ioctl system call for Homa sockets.
 * @return: 0 on success, otherwise a negative errno.
 */
int homa_ioctl(struct sock *sk, int cmd, unsigned long arg) {
	printk(KERN_WARNING "unimplemented ioctl invoked on Homa socket\n");
	return -EINVAL;
}

/**
 * homa_init_sock(): invoked to initialize a new Homa socket.
 * @return: always 0 (success)
 */
int homa_init_sock(struct sock *sk) {
	printk(KERN_NOTICE "Homa socket opened\n");
	return 0;
}

/**
 * homa_setsockopt(): implements the getsockopt system call for Homa sockets.
 * @return: 0 on success, otherwise a negative errno.
 */
int homa_setsockopt(struct sock *sk, int level, int optname,
    char __user *optval, unsigned int optlen) {
	printk(KERN_WARNING "unimplemented setsockopt invoked on Homa socket:"
			" level %d, optname %d, optlen %d\n",
			level, optname, optlen);
	return -EINVAL;
	
}

/**
 * homa_getsockopt(): implements the getsockopt system call for Homa sockets.
 * @return: 0 on success, otherwise a negative errno.
 */
int homa_getsockopt(struct sock *sk, int level, int optname,
    char __user *optval, int __user *option) {
	printk(KERN_WARNING "unimplemented getsockopt invoked on Homa socket:"
			" level %d, optname %d\n", level, optname);
	return -EINVAL;
	
}

/**
 * homa_sendmsg(): send a message on a Homa socket.
 * @return: 0 on success, otherwise a negative errno.
 */
int homa_sendmsg(struct sock *sk, struct msghdr *msg, size_t len) {
	struct inet_sock *inet = inet_sk(sk);
	struct sk_buff *skb;
	__be32 saddr, daddr;
	__be16 dport, sport;
	struct flowi4 fl4;
	struct rtable *rt = NULL;
	int err = 0;
	
	DECLARE_SOCKADDR(struct sockaddr_in *, dest_in, msg->msg_name);
	if (msg->msg_namelen < sizeof(*dest_in))
		return -EINVAL;
	if (dest_in->sin_family != AF_INET) {
		return -EAFNOSUPPORT;
	}
	daddr = dest_in->sin_addr.s_addr;
	saddr = inet->inet_saddr;
	dport = 99;
	sport = 99;
	
	flowi4_init_output(&fl4, sk->sk_bound_dev_if, sk->sk_mark, inet->tos,
			RT_SCOPE_UNIVERSE, sk->sk_protocol,
			0, daddr, saddr, dport, inet->inet_sport,
			sk->sk_uid);
	security_sk_classify_flow(sk, flowi4_to_flowi(&fl4));
	rt = ip_route_output_flow(sock_net(sk), &fl4, sk);
	if (IS_ERR(rt)) {
		err = PTR_ERR(rt);
		goto out;
	}
	
	skb = alloc_skb(1500, GFP_KERNEL);
	if (!skb) {
		printk(KERN_NOTICE "Couldn't allocate sk_buff\n");
		return -ENOMEM;
	}
	skb_reserve(skb, 200);
	err = skb_add_data_nocache(sk, skb, &msg->msg_iter,
		msg_data_left(msg));
	if (err != 0) {
		printk(KERN_NOTICE "Couldn't add data to sk_buff: %d\n",
				err);
		goto out;
	}
	
	skb_dst_set(skb, &rt->dst);
	err = ip_queue_xmit(sk, skb, flowi4_to_flowi(&fl4));
	
out:
	if (rt) {
		ip_rt_put(rt);
	}
	if (err) {
		return err;
	}
	return len;
}

/**
 * homa_recvmsg(): receive a message from a Homa socket.
 * @return: 0 on success, otherwise a negative errno.
 */
int homa_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
		 int noblock, int flags, int *addr_len) {
	printk(KERN_WARNING "unimplemented recvmsg invoked on Homa socket\n");
	return -ENOSYS;
}

/**
 * homa_sendpage(): ??.
 * @return: 0 on success, otherwise a negative errno.
 */
int homa_sendpage(struct sock *sk, struct page *page, int offset,
		  size_t size, int flags) {
	printk(KERN_WARNING "unimplemented sendpage invoked on Homa socket\n");
	return -ENOSYS;
}

/**
 * homa_hash(): ??.
 * @return: ??
 */
int homa_hash(struct sock *sk) {
	printk(KERN_WARNING "unimplemented hash invoked on Homa socket\n");
	return 0;
}

/**
 * homa_unhash(): ??.
 * @return: ??
 */
void homa_unhash(struct sock *sk) {
	printk(KERN_WARNING "unimplemented unhash invoked on Homa socket\n");
}

/**
 * homa_rehash(): ??.
 * @return: ??
 */
void homa_rehash(struct sock *sk) {
	printk(KERN_WARNING "unimplemented rehash invoked on Homa socket\n");
}

/**
 * homa_get_port(): ??.
 * @return: ??
 */
int homa_get_port(struct sock *sk, unsigned short snum) {
	printk(KERN_WARNING "unimplemented get_port invoked on Homa socket\n");
	return 0;
}

/**
 * homa_diag_destroy(): ??.
 * @return: ??
 */
int homa_diag_destroy(struct sock *sk, int err) {
	printk(KERN_WARNING "unimplemented diag_destroy invoked on Homa socket\n");
	return -ENOSYS;
	
}

/**
 * homa_v4_early_demux(): invoked by IP for ??.
 * @return: Always 0?
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
 * homa_handler(): invoked by IP to handle an incoming Homa packet.
 * @return: Always 0?
 */
int homa_handler(struct sk_buff *skb) {
	printk(KERN_NOTICE "incoming Homa packet: len %u, data \"%.*s\"\n",
		skb->len, skb->len, skb->data);
	return 0;
}

/**
 * homa_v4_early_demux_handler(): invoked by IP to handle an incoming error
 * packet, such as ICMP UNREACHABLE.
 * @return: Always 0?
 */
void homa_err_handler(struct sk_buff *skb, u32 info) {
	printk(KERN_WARNING "unimplemented err_handler invoked on Homa socket\n");
}

/**
 * homa_poll(): invoked to implement the poll system call.
 * @return: ??
 */
__poll_t homa_poll(struct file *file, struct socket *sock,
	       struct poll_table_struct *wait) {
	printk(KERN_WARNING "unimplemented poll invoked on Homa socket\n");
	return 0;
}