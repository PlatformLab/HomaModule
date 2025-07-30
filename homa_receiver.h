/* SPDX-License-Identifier: BSD-2-Clause or GPL-2.0+ */

#pragma once

#include <sys/socket.h>
#include <sys/types.h>

extern "C" {
#include "homa.h"
}

namespace homa {
/* Helper class for receiving a series of messages from a Homa socket. This
 * class serves two purposes: first, it implements the application side of
 * the Homa buffer management protocol, returning receive buffer space to
 * Homa when the application longer needs it. Second, it provides convenience
 * methods for accessing messages that are scattered over several discontiguous
 * regions of buffer space.
 *
 * Typical usage:
 * - Call receive, which will invoke Homa to receive an incoming message.
 * - Access the message using methods such as get and copy_out (note: if
 *   the message is shorter than HOMA_BPAGE_SIZE then it will be contiguous).
 * - Call receive to get the next message. This releases all of the resources
 *   associated with the previous message, so you can no longer access that.
 * - Access the new message ...
 *
 * A single homa::receiver allows only a single active incoming message
 * at a time. However, you can create multiple homa::receivers for the
 * same Homa socket, each of which can have one active message. An
 * individual homa::receiver is not thread-safe.
 */
class receiver {
public:
	receiver(int fd, void *buf_regio);
	~receiver();

	/**
	 * homa::receiver::contiguous() - Return a count of the number
	 * of contiguous bytes that are available in the current message
	 * at a given offset. Zero is returned if there is no current message
	 * or the offset is beyond the end of the message.
	 * @offset:  An offset from the beginning of the current message.
	 */
	inline size_t contiguous(size_t offset) const
	{
		if (static_cast<ssize_t>(offset) >= msg_length)
			return 0;
		if ((offset >> HOMA_BPAGE_SHIFT) == (control.num_bpages - 1))
			return msg_length - offset;
		return HOMA_BPAGE_SIZE - (offset & (HOMA_BPAGE_SIZE - 1));
	}

	/**
	 * homa::receiver::completion_cookie() - Return the completion
	 * cookie associated with the current message; result is undefined
	 * if there is no current message.
	 */
	uint64_t completion_cookie(void) const
	{
		return control.completion_cookie;
	}

	void copy_out(void *dest, size_t offset, size_t count) const;

	/**
	 * homa::receiver::get() - Make part of the current message
	 * accessible.
	 * @offset:   Offset within the message of the first byte of an object
	 *            of type T
	 * @storage:  Pointer to a memory region containing at least sizeof(T)
	 *            bytes. If the desired object's bytes are not currently in
	 *            contiguous storage in the message, and if this argument
	 *            is non-null, information is copied out of the message
	 *            into this object so that it is contiguous.
	 * Return:    A pointer to the desired object (either in the message
	 *            or at *storage), or nullptr if the object could not be
	 *            returned (because it extended beyond the end of the
	 *            message, or it wasn't contiguous and storage was nullptr)
	 */
	template<typename T>
	inline T* get(size_t offset, T* storage = nullptr) const {
		int buf_num = offset >> HOMA_BPAGE_SHIFT;

		if (static_cast<ssize_t>(offset + sizeof(T)) > msg_length)
			return nullptr;
		if (contiguous(offset) >= sizeof(T))
			return reinterpret_cast<T*>(buf_region
					+ control.bpage_offsets[buf_num]
					+ (offset & (HOMA_BPAGE_SIZE - 1)));
		if (storage)
			copy_out(storage, offset, sizeof(T));
		return storage;
	}

	/**
	 * id() - Return the Homa RPC identifier for the current message,
	 * or 0 if there is no current message.
	 */
	inline uint64_t id(void) const
	{
		return control.id;
	}

	/**
	 * homa::receiver::is_request() - Return true if the current message
	 * is a request, and false if it is a response or if there is no
	 * current message.
	 */
	bool is_request(void) const
	{
		return control.id & 1;
	}

	/**
	 * homa::receiver::length() - Return the total number of bytes
	 * current message, or a negative value if there is no current
	 * message.
	 */
	ssize_t length(void) const
	{
		return msg_length;
	}

	size_t receive(int flags, uint64_t id);
	void release(void);

	/**
	 * homa::receiver::src_addr() - Return a pointer to the address
	 * of the sender of the current message. The result is undefined
	 * if there is no current message.
	 */
	const struct sockaddr *src_addr(void) const
	{
		return &source.sa;
	}

protected:
	/** @fd: File descriptor for an open Homa socket. */
	int fd;

	/** @hdr: Used to pass information to the recvmsg system call. */
	struct msghdr hdr;

	/**
	 * @control: Additional Homa-specific information passed to the
	 * recvmsg system call through hdr->msg_control. Note: if
	 * num_buffers != 0, it means this contains buffers from a previous
	 * message that must be returned to Homa.
	 */
	struct homa_recvmsg_args control;

	/** @source: Address of the node that sent the current message. */
	union {
		struct sockaddr sa;
		struct sockaddr_in in4;
		struct sockaddr_in6 in6;
	} source;

	/** @length: Length of the current message, or < 0  if none. */
	ssize_t msg_length;

	/** @buf_region: First byte of buffer space for this message. */
	char *buf_region;
};

}    // namespace homa
