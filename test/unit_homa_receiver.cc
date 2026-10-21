// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+

/* Standalone user-space tests: no kernel headers or Homa module required. */
#include <cassert>
#include <cstdarg>
#include <sys/ioctl.h>
#include <cerrno>
#include <cstring>
#include <limits>
#include <vector>
#include "homa_receiver.h"

static int queued_messages;
static int receive_calls;
static int release_calls;
static int release_error;

extern "C" ssize_t recvmsg(int, struct msghdr *hdr, int)
{
	receive_calls++;
	if (queued_messages) {
		queued_messages--;
		auto *args = static_cast<homa_recvmsg_args *>(hdr->msg_control);
		args->id = 101;
		args->num_bpages = 1;
		args->bpage_offsets[0] = 0;
		return 100;
	}
	errno = EAGAIN;
	return -1;
}

extern "C" int ioctl(int, unsigned long cmd, ...) noexcept
{
	assert(cmd == HOMAIOCRELEASE);
	release_calls++;
	if (release_error) {
		errno = release_error;
		return -1;
	}
	va_list ap;
	va_start(ap, cmd);
	auto *args = va_arg(ap, homa_recvmsg_args *);
	va_end(ap);
	args->num_bpages = 0;
	return 0;
}

class test_receiver : public homa::receiver {
public:
	using homa::receiver::receiver;
	void message(ssize_t length) {
		msg_length = length;
		control.num_bpages = length > HOMA_BPAGE_SIZE ? 2 : 1;
		control.bpage_offsets[0] = 0;
		control.bpage_offsets[1] = 2 * HOMA_BPAGE_SIZE;
	}
	unsigned pages() const { return control.num_bpages; }
	void clear() { control.num_bpages = 0; msg_length = -1; }
};

int main()
{
	std::vector<char> region(3 * HOMA_BPAGE_SIZE, 'A');
	std::memset(region.data() + 2 * HOMA_BPAGE_SIZE, 'B', HOMA_BPAGE_SIZE);
	test_receiver r(-1, region.data());
	r.message(100);
	char small[4];
	r.copy_out(small, 0, sizeof(small));
	assert(std::memcmp(small, "AAAA", 4) == 0);

	char clipped[8];
	std::memset(clipped, 'Z', sizeof(clipped));
	r.copy_out(clipped, 98, sizeof(clipped));
	assert(std::memcmp(clipped, "AAZZZZZZ", 8) == 0);
	r.copy_out(clipped, 0, 0);
	r.copy_out(clipped, 100, 1);
	r.copy_out(clipped, std::numeric_limits<size_t>::max(), 1);
	assert(std::memcmp(clipped, "AAZZZZZZ", 8) == 0);

	r.message(HOMA_BPAGE_SIZE + 4);
	char crossing[8];
	r.copy_out(crossing, HOMA_BPAGE_SIZE - 4, sizeof(crossing));
	assert(std::memcmp(crossing, "AAAABBBB", 8) == 0);
	uint64_t storage;
	assert(r.get<uint64_t>(HOMA_BPAGE_SIZE - 4, &storage) == &storage);
	assert(std::memcmp(&storage, "AAAABBBB", 8) == 0);
	assert(r.get<uint64_t>(HOMA_BPAGE_SIZE) == nullptr);
	assert(r.get<char>(std::numeric_limits<size_t>::max()) == nullptr);
	assert(r.contiguous(std::numeric_limits<size_t>::max()) == 0);

	r.message(100);
	queued_messages = 1;
	r.release();
	assert(receive_calls == 0 && queued_messages == 1);
	assert(release_calls == 1 && r.pages() == 0 && r.length() == -1);
	assert(r.receive(MSG_DONTWAIT, 0) == 100);
	assert(queued_messages == 0 && r.id() == 101);
	release_error = EINVAL;
	r.release();
	assert(r.pages() == 1 && r.length() == -1);
	release_error = 0;
	r.release();
	assert(r.pages() == 0);
	int before = release_calls;
	r.release();
	assert(release_calls == before);
	queued_messages = 1;
	{
		test_receiver scoped(-1, region.data());
		scoped.message(100);
	}
	assert(queued_messages == 1 && receive_calls == 1);

	r.clear();
	r.copy_out(clipped, 0, 1);
	assert(r.get<char>(0) == nullptr);
	return 0;
}
