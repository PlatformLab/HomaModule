/* Copyright (c) 2022 Homa Developers
 * SPDX-License-Identifier: BSD-1-Clause
 */

#include <string.h>

#include "homa_receiver.h"

/**
 * homa::receiver::homa() - Constructor for receivers.
 * @fd:         Homa socket from which this object will receive incoming
 *              messages. The caller is responsible for setting up buffering
 *              on the socket using setsockopt with the SO_HOMA_SET_BUF option.
 *              The file descriptor must be valid for the lifetime of this
 *              object.
 * @buf_region: Location of the buffer region that was allocated for
 *              this socket.
 */
homa::receiver::receiver(int fd, void *buf_region)
	: fd(fd)
	, hdr()
	, control()
	, source()
        , msg_length(-1)
        , buf_region(reinterpret_cast<char *>(buf_region))
{
	memset(&hdr, 0, sizeof(hdr));
	hdr.msg_name = &source;
	hdr.msg_namelen = sizeof(source);
	hdr.msg_control = &control;
	hdr.msg_controllen = sizeof(control);

	memset(&control, 0, sizeof(control));
}

/**
 * homa::receiver::~homa() - Destructor for homa::receivers. The main purpose of
 * this destructor is to return any residual buffers to Homa.
 */
homa::receiver::~receiver()
{
	release();
}

/**
 * homa::receiver::copy_out() - Copy data out of the current message.
 * @dest:     Data will be copied here.
 * @offset:   Offset within the message of the first byte to copy.
 * @count:    Number of bytes to copy; if the message doesn't contain
 *            this many bytes starting at offset, then only the
 *            available number of bytes will be copied.
 */
void homa::receiver::copy_out(void *dest, size_t offset, size_t count) const
{
	ssize_t limit = offset + count;
	char *cdest = static_cast<char *>(dest);

	if (limit > msg_length)
		limit = msg_length;
	while (static_cast<ssize_t>(offset) < limit) {
		size_t chunk_size = contiguous(offset);
		memcpy(cdest, get<char>(offset), chunk_size);
		offset += chunk_size;
		cdest += chunk_size;
	}
}

/**
 * homa::receiver::receive() - Release resources for the current message, if
 * any, and receive a new incoming message.
 * @flags:    Various OR'ed bits such as HOMA_RECVMSG_REQUEST and
 *            HOMA_RECVMSG_NONBLOCKING. See the Homa documentation
 *            for the flags field of recvmsg for details.
 * @id:       Identifier of a particular RPC whose result is desired,
 *            or 0. See the Homa documentation for the id field of
 *            recvmsg for details.
 * Return:    The length of the new active message. If an error occurs, -1
 *            is returned and additional information is available in
 *            errno. Note: if id() returns a nonzero result after an
 *            error, it means that that RPC has now completed with an error
 *            and errno describes the nature of the error.
 */
size_t homa::receiver::receive(int flags, uint64_t id)
{
	control.flags = flags;
	control.id = id;
	hdr.msg_namelen = sizeof(source);
	hdr.msg_controllen = sizeof(control);
	msg_length = recvmsg(fd, &hdr, 0);
	if (msg_length < 0) {
		control.num_bpages = 0;
		id = 0;
	}
	return msg_length;
}

/**
 * homa::receiver::release() - Release any resources associated with the
 * current message, if any. The current message must not be accessed again
 * until receive has returned successfully.
 */
void homa::receiver::release()
{
	if (control.num_bpages == 0)
		return;

	/* This recvmsg request will do nothing except return buffer space. */
	control.flags = HOMA_RECVMSG_NONBLOCKING;
	control.id = 0;
	recvmsg(fd, &hdr, 0);
	control.num_bpages = 0;
	msg_length = -1;
}