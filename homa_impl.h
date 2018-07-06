/* This file contains definitions that are shared across the files
 * that implement Homa for Linux.
 */

#include <net/inet_sock.h>

/* Information about an open socket that uses Homa. */
struct homa_sock {
	/* The first part of the structure consists of generic socket data.
	 * This must be the first field. */
	struct inet_sock inet;
	
	/* Everything after here is information specific to Homa sockets. */
};

// Homa's protocol number within the IP protocol space (this is not an
// officially allocated slot).
#define IPPROTO_HOMA 140

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