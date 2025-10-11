/* SPDX-License-Identifier: BSD-2-Clause or GPL-2.0+ WITH Linux-syscall-note */

/* This file defines the kernel call interface for the Homa
 * transport protocol.
 */

#ifndef _UAPI_LINUX_HOMA_H
#define _UAPI_LINUX_HOMA_H

#include <linux/types.h>
#ifndef __KERNEL__
#include <netinet/in.h>
#include <sys/socket.h>
#endif

/* IANA-assigned Internet Protocol number for Homa. */
#define IPPROTO_HOMA 146

/**
 * define HOMA_MAX_MESSAGE_LENGTH - Maximum bytes of payload in a Homa
 * request or response message.
 */
#define HOMA_MAX_MESSAGE_LENGTH 1000000

/**
 * define HOMA_BPAGE_SIZE - Number of bytes in pages used for receive
 * buffers. Must be power of two.
 */
#define HOMA_BPAGE_SIZE (1 << HOMA_BPAGE_SHIFT)
#define HOMA_BPAGE_SHIFT 16

/**
 * define HOMA_MAX_BPAGES - The largest number of bpages that will be required
 * to store an incoming message.
 */
#define HOMA_MAX_BPAGES ((HOMA_MAX_MESSAGE_LENGTH + HOMA_BPAGE_SIZE - 1) >> \
		HOMA_BPAGE_SHIFT)

/**
 * define HOMA_MIN_DEFAULT_PORT - The 16 bit port space is divided into
 * two nonoverlapping regions. Ports 1-32767 are reserved exclusively
 * for well-defined server ports. The remaining ports are used for client
 * ports; these are allocated automatically by Homa. Port 0 is reserved.
 */
#define HOMA_MIN_DEFAULT_PORT 0x8000

/**
 * struct homa_sendmsg_args - Provides information needed by Homa's
 * sendmsg; passed to sendmsg using the msg_control field.
 */
struct homa_sendmsg_args {
	/**
	 * @id: (in/out) An initial value of 0 means a new request is
	 * being sent; nonzero means the message is a reply to the given
	 * id. If the message is a request, then the value is modified to
	 * hold the id of the new RPC.
	 */
	__u64 id;

	/**
	 * @completion_cookie: (in) Used only for request messages; will be
	 * returned by recvmsg when the RPC completes. Typically used to
	 * locate app-specific info about the RPC.
	 */
	__u64 completion_cookie;

	/**
	 * @flags: (in) OR-ed combination of bits that control the operation.
	 * See below for values.
	 */
	__u32 flags;

	/** @reserved: Not currently used, must be 0. */
	__u32 reserved;
};

/* Flag bits for homa_sendmsg_args.flags (see man page for documentation):
 */
#define HOMA_SENDMSG_PRIVATE       0x01
#define HOMA_SENDMSG_VALID_FLAGS   0x01

/**
 * struct homa_recvmsg_args - Provides information needed by Homa's
 * recvmsg; passed to recvmsg using the msg_control field.
 */
struct homa_recvmsg_args {
	/**
	 * @id: (in/out) Initial value is 0 to wait for any shared RPC;
	 * nonzero means wait for that specific (private) RPC. Returns
	 * the id of the RPC received.
	 */
	__u64 id;

	/**
	 * @completion_cookie: (out) If the incoming message is a response,
	 * this will return the completion cookie specified when the
	 * request was sent. For requests this will always be zero.
	 */
	__u64 completion_cookie;

	/**
	 * @num_bpages: (in/out) Number of valid entries in @bpage_offsets.
	 * Passes in bpages from previous messages that can now be
	 * recycled; returns bpages from the new message.
	 */
	__u32 num_bpages;

	/** @reserved: Not currently used, must be 0. */
	__u32 reserved;

	/**
	 * @bpage_offsets: (in/out) Each entry is an offset into the buffer
	 * region for the socket pool. When returned from recvmsg, the
	 * offsets indicate where fragments of the new message are stored. All
	 * entries but the last refer to full buffer pages (HOMA_BPAGE_SIZE
	 * bytes) and are bpage-aligned. The last entry may refer to a bpage
	 * fragment and is not necessarily aligned. The application now owns
	 * these bpages and must eventually return them to Homa, using
	 * bpage_offsets in a future recvmsg invocation.
	 */
	__u32 bpage_offsets[HOMA_MAX_BPAGES];
};

#ifndef __STRIP__ /* See strip.py */
/**
 * struct homa_abort_args - Structure that passes arguments and results
 * between user space and the HOMAIOCABORT ioctl.
 */
struct homa_abort_args {
	/** @id: Id of RPC to abort, or zero to abort all RPCs on socket. */
	__u64 id;

	/**
	 * @error: Zero means destroy and free RPCs; nonzero means complete
	 * them with this error (recvmsg will return the RPCs).
	 */
	__u32 error;

	/** @_pad1: Reserved. */
	__u32 _pad1;

	/** @_pad2: Reserved. */
	__u64 _pad2[2];
};
#endif /* See strip.py */

/** define SO_HOMA_RCVBUF: setsockopt option for specifying buffer region. */
#define SO_HOMA_RCVBUF 10

/**
 * define SO_HOMA_SERVER: setsockopt option for specifying whether a
 * socket will act as server.
 */
#define SO_HOMA_SERVER 11

/** struct homa_rcvbuf_args - setsockopt argument for SO_HOMA_RCVBUF. */
struct homa_rcvbuf_args {
	/** @start: Address of first byte of buffer region in user space. */
	__u64 start;

	/** @length: Total number of bytes available at @start. */
	size_t length;
};

/* Meanings of the bits in Homa's flag word, which can be set using
 * "sysctl /net/homa/flags".
 */

/**
 * define HOMA_FLAG_DONT_THROTTLE - disable the output throttling mechanism
 * (always send all packets immediately).
 */
#define HOMA_FLAG_DONT_THROTTLE   2

/**
 * struct homa_rpc_info - Used by HOMAIOCINFO to return information about
 * a specific RPC.
 */
struct homa_rpc_info {
	/**
	 * @id: Identifier for the RPC, unique among all RPCs sent by the
	 * client node. If the low-order bit is 1, this node is the server
	 * for the RPC; 0 means we are the client.
	 */
	__u64 id;

	/** @peer: Address of the peer socket for this RPC. */
	union {
		struct sockaddr_storage storage;
		struct sockaddr_in in4;
		struct sockaddr_in6 in6;
	} peer;

	/**
	 * @completion_cookie: For client-side RPCs this gives the completion
	 * cookie specified when the RPC was initiated. For server-side RPCs
	 * this is zero.
	 */
	__u64 completion_cookie;

	/**
	 * @tx_length: Length of the outgoing message in bytes, or -1 if
	 * the sendmsg hasn't yet been called.
	 */
	__s32 tx_length;

	/**
	 * @tx_sent: Number of bytes of the outgoing message that have been
	 * transmitted at least once.
	 */
	__u32 tx_sent;

	/**
	 * @tx_granted: Number of bytes of the outgoing message that the
	 * receiver has authorized us to transmit (includes unscheduled
	 * bytes).
	 */
	__u32 tx_granted;

	/**
	 * @tx_prio: Current priority level that the receiver has specified
	 * for transmitting packets.
	 */
	__u32 tx_prio;

	/**
	 * @rx_length: Length of the incoming message, in bytes. -1 means
	 * the length is not yet known (this is a client-side RPC and
	 * no packets have been received).
	 */
	__s32 rx_length;

	/**
	 * @rx_received: Number of bytes in the incoming message that have
	 * not yet been received.
	 */
	__u32 rx_remaining;

	/**
	 * @rx_gaps: The number of gaps in the incoming message. A gap is
	 * a range of bytes that have not been received yet, but bytes after
	 * the gap have been received.
	 */
	__u32 rx_gaps;

	/**
	 * @rx_gap_bytes: The total number of bytes in gaps in the incoming
	 * message.
	 */
	__u32 rx_gap_bytes;

	/**
	 * @rx_granted: The number of bytes in the message that the sender
	 * is authorized to transmit (includes unscheduled bytes).
	 */
	__u32 rx_granted;

	/**
	 * @flags: Various single-bit values associated with the RPC:
	 * HOMA_RPC_BUF_STALL:  The incoming message is currently stalled
	 *                      because there is insufficient receiver buffer
	 *                      space.
	 * HOMA_RPC_PRIVATE:    The RPC has been created as "private"; set
	 *                      only on the client side.
	 * HOMA_RPC_RX_READY:   The incoming message is complete and has
	 *                      been queued waiting for a thread to call
	 *                      recvmsg.
	 * HOMA_RPC_RX_COPY:    There are packets that have been received,
	 *                      whose data has not yet been copied from
	 *                      packet buffers to user space.
	 */
	__u16 flags;
#define HOMA_RPC_BUF_STALL    1
#define HOMA_RPC_PRIVATE      2
#define HOMA_RPC_RX_READY     4
#define HOMA_RPC_RX_COPY      8
};

/**
 * struct homa_info - In/out argument passed to HOMAIOCINFO. Fields labeled
 * as "in" must be set by the application; other fields are returned to the
 * application from the kernel.
 */
struct homa_info {
	/**
	 * @rpc_info: (in) Address of memory region in which to store infomation
	 * about individual RPCs.
	 */
	struct homa_rpc_info *rpc_info;

	/**
	 * @rpc_info_length: (in) Number of bytes of storage available at
	 * rpc_info.
	 */
	size_t rpc_info_length;

	/**
	 * @bpool_avail_bytes: Number of bytes in the buffer pool for incoming
	 * messages that is currently available for new messages.
	 */
	__u64 bpool_avail_bytes;

	/** @port: Port number handled by this socket. */
	__u32 port;

	/**
	 * @num_rpcs: Total number of active RPCs (both server and client) for
	 * this socket. The number stored at @rpc_info will be less than this
	 * if @rpc_info_length is too small.
	 */
	__u32 num_rpcs;

	/**
	 * @error_msg: Provides additional information about the last error
	 * returned by a Homa-related kernel call such as sendmsg, recvmsg,
	 * or ioctl. Not updated for some obvious return values such as EINTR
	 * or EWOULDBLOCK.
	 */
#define HOMA_ERROR_MSG_SIZE 100
	char error_msg[HOMA_ERROR_MSG_SIZE];
};

/* I/O control calls on Homa sockets.*/
#define HOMAIOCINFO  _IOWR('h', 1, struct homa_info)
#ifndef __STRIP__ /* See strip.py */
#define HOMAIOCABORT  _IOWR('h', 2, struct homa_abort_args)
#define HOMAIOCFREEZE _IO('h', 3)
#endif /* See strip.py */

#endif /* _UAPI_LINUX_HOMA_H */
