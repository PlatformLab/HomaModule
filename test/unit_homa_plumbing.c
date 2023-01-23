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

#include "homa_impl.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

extern struct homa *homa;

FIXTURE(homa_plumbing) {
	struct in6_addr client_ip[1];
	int client_port;
	struct in6_addr server_ip[1];
	int server_port;
	__u64 client_id;
	__u64 server_id;
	struct homa homa;
	struct homa_sock hsk;
	sockaddr_in_union client_addr;
	sockaddr_in_union server_addr;
	struct data_header data;
	int starting_skb_count;
	struct msghdr recvmsg_hdr;
	struct homa_recvmsg_args recvmsg_args;
	struct iovec send_vec[2];
	struct msghdr sendmsg_hdr;
	struct homa_sendmsg_args sendmsg_args;
	char buffer[2000];
	sockptr_t optval;
	sockaddr_in_union addr;
};
FIXTURE_SETUP(homa_plumbing)
{
	self->client_ip[0] = unit_get_in_addr("196.168.0.1");
	self->client_port = 40000;
	self->server_ip[0] = unit_get_in_addr("1.2.3.4");
	self->server_port = 99;
	self->client_id = 1234;
	self->server_id = 1235;
	self->client_addr.in6.sin6_addr = self->client_ip[0];
	self->client_addr.in6.sin6_port = htons(self->client_port);
	self->server_addr.in6.sin6_addr = self->server_ip[0];
	self->server_addr.in6.sin6_port = htons(self->server_port);
	homa = &self->homa;
	homa_init(&self->homa);
	mock_sock_init(&self->hsk, &self->homa, 0);
	self->client_addr.in6.sin6_family = self->hsk.inet.sk.sk_family;
	self->server_addr.in6.sin6_family = self->hsk.inet.sk.sk_family;
	if (self->hsk.inet.sk.sk_family == AF_INET) {
		self->client_addr.in4.sin_addr.s_addr =
			ipv6_to_ipv4(self->client_addr.in6.sin6_addr);
		self->server_addr.in4.sin_addr.s_addr =
			ipv6_to_ipv4(self->server_addr.in6.sin6_addr);
	}
	homa_sock_bind(&self->homa.port_map, &self->hsk, self->server_port);
	self->data = (struct data_header){.common = {
			.sport = htons(self->client_port),
	                .dport = htons(self->server_port),
			.type = DATA,
			.sender_id = cpu_to_be64(self->client_id)},
			.message_length = htonl(10000),
			.incoming = htonl(10000), .retransmit = 0,
			.seg={.offset = 0}};
	self->recvmsg_args.id = 0;
	self->recvmsg_hdr.msg_name = &self->addr;
	self->recvmsg_hdr.msg_namelen = 0;
	self->recvmsg_hdr.msg_control = &self->recvmsg_args;
	self->recvmsg_hdr.msg_controllen = sizeof(self->recvmsg_args);
	self->recvmsg_hdr.msg_flags = 0;
	memset(&self->recvmsg_args, 0, sizeof(self->recvmsg_args));
	self->recvmsg_args.flags = HOMA_RECVMSG_REQUEST
			| HOMA_RECVMSG_RESPONSE | HOMA_RECVMSG_NONBLOCKING;
	self->send_vec[0].iov_base = self->buffer;
	self->send_vec[0].iov_len = 100;
	self->send_vec[1].iov_base = self->buffer + 1000;
	self->send_vec[1].iov_len = 100;
	self->sendmsg_hdr.msg_name = &self->client_addr;
	self->sendmsg_hdr.msg_namelen = sizeof(self->client_addr);
	iov_iter_init(&self->sendmsg_hdr.msg_iter, WRITE, self->send_vec,
			2, 200);
	self->sendmsg_hdr.msg_control = &self->sendmsg_args;
	self->sendmsg_hdr.msg_controllen = sizeof(self->sendmsg_args);
	self->sendmsg_hdr.msg_control_is_user = 1;
	self->sendmsg_args.id = 0;
	self->sendmsg_args.completion_cookie = 0;
	self->optval.user = (void *) 0x100000;
	self->optval.is_kernel = 0;
	unit_log_clear();
}
FIXTURE_TEARDOWN(homa_plumbing)
{
	homa_destroy(&self->homa);
	unit_teardown();
	homa = NULL;
}

TEST_F(homa_plumbing, homa_bind__version_mismatch)
{
	// Make sure the test uses IPv4.
	mock_ipv6 = false;
	homa_sock_destroy(&self->hsk);
	mock_sock_init(&self->hsk, &self->homa, 0);

	struct sockaddr addr = {};
	addr.sa_family = AF_INET6;
	struct socket sock = {};
	sock.sk = &self->hsk.inet.sk;
	int result = homa_bind(&sock, &addr, sizeof(addr));
	EXPECT_EQ(EAFNOSUPPORT, -result);
}
TEST_F(homa_plumbing, homa_bind__ipv6_address_too_short)
{
	// Make sure the test uses IPv6.
	mock_ipv6 = true;
	homa_sock_destroy(&self->hsk);
	mock_sock_init(&self->hsk, &self->homa, 0);

	sockaddr_in_union addr = {};
	addr.in6.sin6_family = AF_INET6;
	struct socket sock = {};
	sock.sk = &self->hsk.inet.sk;
	int result = homa_bind(&sock, &addr.sa, sizeof(addr.in6)-1);
	EXPECT_EQ(EINVAL, -result);
}
TEST_F(homa_plumbing, homa_bind__ipv6_ok)
{
	// Make sure the test uses IPv6.
	mock_ipv6 = true;
	homa_sock_destroy(&self->hsk);
	mock_sock_init(&self->hsk, &self->homa, 0);

	sockaddr_in_union addr = {};
	addr.in6.sin6_family = AF_INET6;
	addr.in6.sin6_port = htons(123);
	struct socket sock = {};
	sock.sk = &self->hsk.inet.sk;
	int result = homa_bind(&sock, &addr.sa, sizeof(addr.in6));
	EXPECT_EQ(0, -result);
	EXPECT_EQ(123, self->hsk.port);
}
TEST_F(homa_plumbing, homa_bind__ipv4_address_too_short)
{
	// Make sure the test uses IPv4.
	mock_ipv6 = false;
	homa_sock_destroy(&self->hsk);
	mock_sock_init(&self->hsk, &self->homa, 0);

	sockaddr_in_union addr = {};
	addr.in4.sin_family = AF_INET;
	struct socket sock = {};
	sock.sk = &self->hsk.inet.sk;
	int result = homa_bind(&sock, &addr.sa, sizeof(addr.in4)-1);
	EXPECT_EQ(EINVAL, -result);
}
TEST_F(homa_plumbing, homa_bind__ipv4_ok)
{
	// Make sure the test uses IPv4.
	mock_ipv6 = false;
	homa_sock_destroy(&self->hsk);
	mock_sock_init(&self->hsk, &self->homa, 0);

	sockaddr_in_union addr = {};
	addr.in4.sin_family = AF_INET;
	addr.in4.sin_port = htons(345);
	struct socket sock = {};
	sock.sk = &self->hsk.inet.sk;
	int result = homa_bind(&sock, &addr.sa, sizeof(addr.in4));
	EXPECT_EQ(0, -result);
	EXPECT_EQ(345, self->hsk.port);
}

TEST_F(homa_plumbing, homa_ioc_abort__basics)
{
	struct homa_abort_args args = {self->client_id, 0};
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 10000, 200);
	ASSERT_NE(NULL, crpc);
	EXPECT_EQ(0, homa_ioc_abort(&self->hsk.inet.sk, (unsigned long) &args));
	EXPECT_EQ(RPC_DEAD, crpc->state);
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
}
TEST_F(homa_plumbing, homa_ioc_abort__cant_read_user_args)
{
	struct homa_abort_args args = {self->client_id, 0};
	mock_copy_data_errors = 1;
	EXPECT_EQ(EFAULT, -homa_ioc_abort(&self->hsk.inet.sk,
			(unsigned long) &args));
}
TEST_F(homa_plumbing, homa_ioc_abort__abort_multiple_rpcs)
{
	struct homa_abort_args args = {0, ECANCELED};
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 10000, 200);
	struct homa_rpc *crpc2 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 10000, 200);
	ASSERT_NE(NULL, crpc1);
	ASSERT_NE(NULL, crpc2);
	EXPECT_EQ(0, homa_ioc_abort(&self->hsk.inet.sk, (unsigned long) &args));
	EXPECT_EQ(-ECANCELED, crpc1->error);
	EXPECT_EQ(-ECANCELED, crpc2->error);
	EXPECT_EQ(2, unit_list_length(&self->hsk.active_rpcs));
}
TEST_F(homa_plumbing, homa_ioc_abort__nonexistent_rpc)
{
	struct homa_abort_args args = {99, 0};
	EXPECT_EQ(EINVAL, -homa_ioc_abort(&self->hsk.inet.sk,
			(unsigned long) &args));
}

TEST_F(homa_plumbing, homa_set_sock_opt__bad_level)
{
	EXPECT_EQ(EINVAL, -homa_setsockopt(&self->hsk.sock, 0, 0,
		self->optval, sizeof(struct homa_set_buf_args)));
}
TEST_F(homa_plumbing, homa_set_sock_opt__bad_optname)
{
	EXPECT_EQ(EINVAL, -homa_setsockopt(&self->hsk.sock, IPPROTO_HOMA, 0,
		self->optval, sizeof(struct homa_set_buf_args)));
}
TEST_F(homa_plumbing, homa_set_sock_opt__bad_optlen)
{
	EXPECT_EQ(EINVAL, -homa_setsockopt(&self->hsk.sock, IPPROTO_HOMA,
			SO_HOMA_SET_BUF, self->optval,
			sizeof(struct homa_set_buf_args) - 1));
}
TEST_F(homa_plumbing, homa_set_sock_opt__copy_from_sockptr_fails)
{
	mock_copy_data_errors = 1;
	EXPECT_EQ(EFAULT, -homa_setsockopt(&self->hsk.sock, IPPROTO_HOMA,
			SO_HOMA_SET_BUF, self->optval,
			sizeof(struct homa_set_buf_args)));
}
TEST_F(homa_plumbing, homa_set_sock_opt__copy_to_user_fails)
{
	struct homa_set_buf_args args = {(void *) 0x100000, 5*HOMA_BPAGE_SIZE};
	self->optval.user = &args;
	mock_copy_to_user_errors = 1;
	EXPECT_EQ(EFAULT, -homa_setsockopt(&self->hsk.sock, IPPROTO_HOMA,
			SO_HOMA_SET_BUF, self->optval,
			sizeof(struct homa_set_buf_args)));
}
TEST_F(homa_plumbing, homa_set_sock_opt__success)
{
	struct homa_set_buf_args args;
	char buffer[5000];

	args.start = (void *) (((__u64) (buffer + PAGE_SIZE - 1))
			& ~(PAGE_SIZE - 1));
	args.length = 5*HOMA_BPAGE_SIZE;
	self->optval.user = &args;
	EXPECT_EQ(0, -homa_setsockopt(&self->hsk.sock, IPPROTO_HOMA,
			SO_HOMA_SET_BUF, self->optval,
			sizeof(struct homa_set_buf_args)));
	EXPECT_EQ(args.start, self->hsk.buffer_pool.region);
	EXPECT_EQ(5, self->hsk.buffer_pool.num_bpages);
	EXPECT_EQ(1, homa_cores[cpu_number]->metrics.so_set_buf_calls);
}

TEST_F(homa_plumbing, homa_sendmsg__args_not_in_user_space)
{
	self->sendmsg_hdr.msg_control_is_user = 0;
	EXPECT_EQ(EINVAL, -homa_sendmsg(&self->hsk.inet.sk,
		&self->sendmsg_hdr, self->sendmsg_hdr.msg_iter.count));
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
}
TEST_F(homa_plumbing, homa_sendmsg__cant_read_args)
{
	mock_copy_data_errors = 1;
	EXPECT_EQ(EFAULT, -homa_sendmsg(&self->hsk.inet.sk,
		&self->sendmsg_hdr, self->sendmsg_hdr.msg_iter.count));
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
}
TEST_F(homa_plumbing, homa_sendmsg__bad_address_family)
{
	self->client_addr.in4.sin_family = 1;
	EXPECT_EQ(EAFNOSUPPORT, -homa_sendmsg(&self->hsk.inet.sk,
		&self->sendmsg_hdr, self->sendmsg_hdr.msg_iter.count));
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
}
TEST_F(homa_plumbing, homa_sendmsg__address_too_short)
{
	self->client_addr.in4.sin_family = AF_INET;
	self->hsk.inet.sk.sk_family = AF_INET;
	self->sendmsg_hdr.msg_namelen = sizeof(struct sockaddr_in) - 1;
	EXPECT_EQ(EINVAL, -homa_sendmsg(&self->hsk.inet.sk,
		&self->sendmsg_hdr, self->sendmsg_hdr.msg_iter.count));
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));

	self->client_addr.in4.sin_family = AF_INET6;
	self->hsk.inet.sk.sk_family = AF_INET6;
	self->sendmsg_hdr.msg_namelen = sizeof(struct sockaddr_in6) - 1;
	EXPECT_EQ(EINVAL, -homa_sendmsg(&self->hsk.inet.sk,
		&self->sendmsg_hdr, self->sendmsg_hdr.msg_iter.count));
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
}
TEST_F(homa_plumbing, homa_sendmsg__error_in_homa_rpc_new_client)
{
	mock_kmalloc_errors = 2;
	EXPECT_EQ(ENOMEM, -homa_sendmsg(&self->hsk.inet.sk,
		&self->sendmsg_hdr, self->sendmsg_hdr.msg_iter.count));
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
}
TEST_F(homa_plumbing, homa_sendmsg__cant_update_user_arguments)
{
	mock_copy_to_user_errors = 1;
	atomic64_set(&self->homa.next_outgoing_id, 1234);
	EXPECT_EQ(EFAULT, -homa_sendmsg(&self->hsk.inet.sk,
		&self->sendmsg_hdr, self->sendmsg_hdr.msg_iter.count));
	EXPECT_SUBSTR("xmit DATA 200@0", unit_log_get());
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
}
TEST_F(homa_plumbing, homa_sendmsg__request_sent_successfully)
{
	struct homa_rpc *crpc;
	atomic64_set(&self->homa.next_outgoing_id, 1234);
	self->sendmsg_args.completion_cookie = 88888;
	EXPECT_EQ(0, -homa_sendmsg(&self->hsk.inet.sk,
		&self->sendmsg_hdr, self->sendmsg_hdr.msg_iter.count));
	EXPECT_SUBSTR("xmit DATA 200@0", unit_log_get());
	EXPECT_EQ(1234L, self->sendmsg_args.id);
	ASSERT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
	crpc = homa_find_client_rpc(&self->hsk, self->sendmsg_args.id);
	ASSERT_NE(NULL, crpc);
	EXPECT_EQ(88888, crpc->completion_cookie);
	homa_rpc_unlock(crpc);
}
TEST_F(homa_plumbing, homa_sendmsg__response_nonzero_completion_cookie)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, UNIT_IN_SERVICE,
			self->client_ip, self->server_ip, self->client_port,
		        self->server_id, 2000, 100);
	self->sendmsg_args.id = self->server_id;
	self->sendmsg_args.completion_cookie = 12345;
	EXPECT_EQ(EINVAL, -homa_sendmsg(&self->hsk.inet.sk,
		&self->sendmsg_hdr, self->sendmsg_hdr.msg_iter.count));
	EXPECT_EQ(RPC_IN_SERVICE, srpc->state);
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
}
TEST_F(homa_plumbing, homa_sendmsg__response_cant_find_peer)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, UNIT_IN_SERVICE,
			self->client_ip, self->server_ip, self->client_port,
		        self->server_id, 2000, 100);
	self->sendmsg_hdr.msg_name = &self->server_addr;
	self->sendmsg_args.id = self->server_id;
	mock_kmalloc_errors = 1;
	EXPECT_EQ(ENOMEM, -homa_sendmsg(&self->hsk.inet.sk,
		&self->sendmsg_hdr, self->sendmsg_hdr.msg_iter.count));
	EXPECT_EQ(RPC_IN_SERVICE, srpc->state);
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
}
TEST_F(homa_plumbing, homa_sendmsg__response_cant_fill_packets)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, UNIT_IN_SERVICE,
			self->client_ip, self->server_ip, self->client_port,
		        self->server_id, 2000, 100);
	self->sendmsg_args.id = self->server_id;
	self->sendmsg_hdr.msg_iter.count = HOMA_MAX_MESSAGE_LENGTH + 1;
	EXPECT_EQ(EINVAL, -homa_sendmsg(&self->hsk.inet.sk,
		&self->sendmsg_hdr, self->sendmsg_hdr.msg_iter.count));
	EXPECT_EQ(RPC_IN_SERVICE, srpc->state);
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
}
TEST_F(homa_plumbing, homa_sendmsg__response_cant_find_rpc)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, UNIT_IN_SERVICE,
			self->client_ip, self->server_ip, self->client_port,
		        self->server_id, 2000, 100);
	self->sendmsg_args.id = self->server_id + 1;
	EXPECT_EQ(EINVAL, -homa_sendmsg(&self->hsk.inet.sk,
		&self->sendmsg_hdr, self->sendmsg_hdr.msg_iter.count));
	EXPECT_EQ(RPC_IN_SERVICE, srpc->state);
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
}
TEST_F(homa_plumbing, homa_sendmsg__response_error_in_rpc)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, UNIT_IN_SERVICE,
			self->client_ip, self->server_ip, self->client_port,
		        self->server_id, 2000, 100);
	self->sendmsg_args.id = srpc->id;
	srpc->error = -ENOMEM;
	EXPECT_EQ(ENOMEM, -homa_sendmsg(&self->hsk.inet.sk,
		&self->sendmsg_hdr, self->sendmsg_hdr.msg_iter.count));
	EXPECT_EQ(RPC_DEAD, srpc->state);
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
}
TEST_F(homa_plumbing, homa_sendmsg__response_wrong_state)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, UNIT_RCVD_ONE_PKT,
			self->client_ip, self->server_ip, self->client_port,
		        self->server_id, 2000, 100);
	self->sendmsg_args.id = self->server_id;
	EXPECT_EQ(EINVAL, -homa_sendmsg(&self->hsk.inet.sk,
		&self->sendmsg_hdr, self->sendmsg_hdr.msg_iter.count));
	EXPECT_EQ(RPC_INCOMING, srpc->state);
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
}
TEST_F(homa_plumbing, homa_sendmsg__response_succeeds)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, UNIT_IN_SERVICE,
			self->client_ip, self->server_ip, self->client_port,
		        self->server_id, 2000, 100);
	self->sendmsg_args.id = self->server_id;
	EXPECT_EQ(0, -homa_sendmsg(&self->hsk.inet.sk,
		&self->sendmsg_hdr, self->sendmsg_hdr.msg_iter.count));
	EXPECT_EQ(RPC_OUTGOING, srpc->state);
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
}

TEST_F(homa_plumbing, homa_recvmsg__wrong_args_length)
{
	self->recvmsg_hdr.msg_controllen -= 1;
	EXPECT_EQ(EINVAL, -homa_recvmsg(&self->hsk.inet.sk, &self->recvmsg_hdr,
			0, 0, 0, &self->recvmsg_hdr.msg_namelen));
}
TEST_F(homa_plumbing, homa_recvmsg__cant_read_args)
{
	mock_copy_data_errors = 1;
	EXPECT_EQ(EFAULT, -homa_recvmsg(&self->hsk.inet.sk, &self->recvmsg_hdr,
			0, 0, 0, &self->recvmsg_hdr.msg_namelen));
}
TEST_F(homa_plumbing, homa_recvmsg__clear_cookie)
{
	// Make sure that the completion_cookie will be zero if anything
	// goes wrong with the receive.
	self->recvmsg_args._pad[0] = 1;
	self->recvmsg_args.completion_cookie = 12345;
	EXPECT_EQ(EINVAL, -homa_recvmsg(&self->hsk.inet.sk, &self->recvmsg_hdr,
			0, 0, 0, &self->recvmsg_hdr.msg_namelen));
	EXPECT_EQ(0, self->recvmsg_args.completion_cookie);
}
TEST_F(homa_plumbing, homa_recvmsg__pad_not_zero)
{
	self->recvmsg_args._pad[0] = 1;
	EXPECT_EQ(EINVAL, -homa_recvmsg(&self->hsk.inet.sk, &self->recvmsg_hdr,
			0, 0, 0, &self->recvmsg_hdr.msg_namelen));
}
TEST_F(homa_plumbing, homa_recvmsg__num_bpages_too_large)
{
	self->recvmsg_args.num_bpages = HOMA_MAX_BPAGES + 1;
	EXPECT_EQ(EINVAL, -homa_recvmsg(&self->hsk.inet.sk, &self->recvmsg_hdr,
			0, 0, 0, &self->recvmsg_hdr.msg_namelen));
}
TEST_F(homa_plumbing, homa_recvmsg__bogus_flags)
{
	self->recvmsg_args.flags = 1 << 10;
	EXPECT_EQ(EINVAL, -homa_recvmsg(&self->hsk.inet.sk, &self->recvmsg_hdr,
			0, 0, 0, &self->recvmsg_hdr.msg_namelen));
}
TEST_F(homa_plumbing, homa_recvmsg__release_buffers)
{
	EXPECT_EQ(0, -homa_pool_init(&self->hsk.buffer_pool, &self->homa,
			(char *) 0x1000000, 100*HOMA_BPAGE_SIZE));
	EXPECT_EQ(0, -homa_pool_get_pages(&self->hsk.buffer_pool, 2,
			self->recvmsg_args.bpage_offsets, 0));
	EXPECT_EQ(1, atomic_read(&self->hsk.buffer_pool.descriptors[0].refs));
	EXPECT_EQ(1, atomic_read(&self->hsk.buffer_pool.descriptors[1].refs));
	self->recvmsg_args.num_bpages = 2;
	self->recvmsg_args.bpage_offsets[0] = 0;
	self->recvmsg_args.bpage_offsets[1] = HOMA_BPAGE_SIZE;

	EXPECT_EQ(EAGAIN, -homa_recvmsg(&self->hsk.inet.sk, &self->recvmsg_hdr,
			0, 0, 0, &self->recvmsg_hdr.msg_namelen));
	EXPECT_EQ(0, atomic_read(&self->hsk.buffer_pool.descriptors[0].refs));
	EXPECT_EQ(0, atomic_read(&self->hsk.buffer_pool.descriptors[1].refs));
}
TEST_F(homa_plumbing, homa_recvmsg__nonblocking_argument)
{
	self->recvmsg_args.flags = HOMA_RECVMSG_REQUEST;
	EXPECT_EQ(EAGAIN, -homa_recvmsg(&self->hsk.inet.sk, &self->recvmsg_hdr,
			0, 1, 0, &self->recvmsg_hdr.msg_namelen));
}
TEST_F(homa_plumbing, homa_recvmsg__error_in_homa_wait_for_message)
{
	self->hsk.shutdown = true;
	EXPECT_EQ(ESHUTDOWN, -homa_recvmsg(&self->hsk.inet.sk,
			&self->recvmsg_hdr, 0, 0, 0,
			&self->recvmsg_hdr.msg_namelen));
	self->hsk.shutdown = false;
}
TEST_F(homa_plumbing, homa_recvmsg__normal_completion_ipv4)
{
	// Make sure the test uses IPv4.
	mock_ipv6 = false;
	homa_sock_destroy(&self->hsk);
	mock_sock_init(&self->hsk, &self->homa, 0);
	__u32 pages[2];

	EXPECT_EQ(0, -homa_pool_init(&self->hsk.buffer_pool, &self->homa,
			(char *) 0x1000000, 100*HOMA_BPAGE_SIZE));
	EXPECT_EQ(0, -homa_pool_get_pages(&self->hsk.buffer_pool, 2, pages, 0));
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_MSG,
			self->client_ip, self->server_ip, self->server_port,
			self->client_id, 100, 2000);
	EXPECT_NE(NULL, crpc);
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
	crpc->completion_cookie = 44444;

	EXPECT_EQ(2000, homa_recvmsg(&self->hsk.inet.sk, &self->recvmsg_hdr,
			0, 0, 0, &self->recvmsg_hdr.msg_namelen));
	EXPECT_EQ(self->client_id, self->recvmsg_args.id);
	EXPECT_EQ(44444, self->recvmsg_args.completion_cookie);
	EXPECT_EQ(AF_INET, self->addr.in4.sin_family);
	EXPECT_STREQ("1.2.3.4", homa_print_ipv4_addr(
			self->addr.in4.sin_addr.s_addr));
	EXPECT_EQ(sizeof32(struct sockaddr_in),
			self->recvmsg_hdr.msg_namelen);
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_EQ(1, self->recvmsg_args.num_bpages);
	EXPECT_EQ(2*HOMA_BPAGE_SIZE, self->recvmsg_args.bpage_offsets[0]);
	EXPECT_EQ(sizeof(struct homa_recvmsg_args),
			(char *) self->recvmsg_hdr.msg_control
			- (char *) &self->recvmsg_args);
}
TEST_F(homa_plumbing, homa_recvmsg__normal_completion_ipv6)
{
	// Make sure the test uses IPv6.
	mock_ipv6 = true;
	homa_sock_destroy(&self->hsk);
	mock_sock_init(&self->hsk, &self->homa, 0);
	struct in6_addr server_ip6 = unit_get_in_addr("1::3:5:7");

	EXPECT_EQ(0, -homa_pool_init(&self->hsk.buffer_pool, &self->homa,
			(char *) 0x1000000, 100*HOMA_BPAGE_SIZE));
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_MSG,
			self->client_ip, &server_ip6, self->server_port,
			self->client_id, 100, 2000);
	EXPECT_NE(NULL, crpc);
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
	crpc->completion_cookie = 44444;

	EXPECT_EQ(2000, homa_recvmsg(&self->hsk.inet.sk, &self->recvmsg_hdr,
			0, 0, 0, &self->recvmsg_hdr.msg_namelen));
	EXPECT_EQ(self->client_id, self->recvmsg_args.id);
	EXPECT_EQ(44444, self->recvmsg_args.completion_cookie);
	EXPECT_EQ(AF_INET6, self->addr.in6.sin6_family);
	EXPECT_STREQ("[1::3:5:7]", homa_print_ipv6_addr(
			&self->addr.in6.sin6_addr));
	EXPECT_EQ(sizeof32(struct sockaddr_in6),
			self->recvmsg_hdr.msg_namelen);
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_EQ(0, crpc->msgin.num_bpages);
}
TEST_F(homa_plumbing, homa_recvmsg__rpc_has_error)
{
	EXPECT_EQ(0, -homa_pool_init(&self->hsk.buffer_pool, &self->homa,
			(char *) 0x1000000, 100*HOMA_BPAGE_SIZE));
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->server_port,
			self->client_id, 100, 2000);
	EXPECT_NE(NULL, crpc);
	crpc->completion_cookie = 44444;
	homa_rpc_abort(crpc, -ETIMEDOUT);

	EXPECT_EQ(ETIMEDOUT, -homa_recvmsg(&self->hsk.inet.sk,
			&self->recvmsg_hdr, 0, 0, 0,
			&self->recvmsg_hdr.msg_namelen));
	EXPECT_EQ(self->client_id, self->recvmsg_args.id);
	EXPECT_EQ(44444, self->recvmsg_args.completion_cookie);
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_EQ(0, self->recvmsg_args.num_bpages);
}
TEST_F(homa_plumbing, homa_recvmsg__add_ack)
{
	EXPECT_EQ(0, -homa_pool_init(&self->hsk.buffer_pool, &self->homa,
			(char *) 0x1000000, 100*HOMA_BPAGE_SIZE));
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_MSG,
			self->client_ip, self->server_ip, self->server_port,
			self->client_id, 100, 2000);
	EXPECT_NE(NULL, crpc);
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
	crpc->completion_cookie = 44444;

	EXPECT_EQ(2000, homa_recvmsg(&self->hsk.inet.sk, &self->recvmsg_hdr,
			0, 0, 0, &self->recvmsg_hdr.msg_namelen));
	EXPECT_EQ(1, crpc->peer->num_acks);
}
TEST_F(homa_plumbing, homa_recvmsg__server_normal_completion)
{
	EXPECT_EQ(0, -homa_pool_init(&self->hsk.buffer_pool, &self->homa,
			(char *) 0x1000000, 100*HOMA_BPAGE_SIZE));
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, UNIT_RCVD_MSG,
			self->client_ip, self->server_ip, self->client_port,
		        self->server_id, 100, 200);
	EXPECT_NE(NULL, srpc);

	EXPECT_EQ(100, homa_recvmsg(&self->hsk.inet.sk, &self->recvmsg_hdr,
			0, 0, 0, &self->recvmsg_hdr.msg_namelen));
	EXPECT_EQ(self->server_id, self->recvmsg_args.id);
	EXPECT_EQ(RPC_IN_SERVICE, srpc->state);
	EXPECT_EQ(0, srpc->peer->num_acks);
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
}
TEST_F(homa_plumbing, homa_recvmsg__delete_server_rpc_after_error)
{
	EXPECT_EQ(0, -homa_pool_init(&self->hsk.buffer_pool, &self->homa,
			(char *) 0x1000000, 100*HOMA_BPAGE_SIZE));
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, UNIT_RCVD_MSG,
			self->client_ip, self->server_ip, self->client_port,
		        self->server_id, 100, 200);
	EXPECT_NE(NULL, srpc);
	srpc->error = -ENOMEM;

	EXPECT_EQ(ENOMEM, -homa_recvmsg(&self->hsk.inet.sk, &self->recvmsg_hdr,
			0, 0, 0, &self->recvmsg_hdr.msg_namelen));
	EXPECT_EQ(self->server_id, self->recvmsg_args.id);
	EXPECT_EQ(RPC_DEAD, srpc->state);
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
}
TEST_F(homa_plumbing, homa_recvmsg__error_copying_out_args)
{
	EXPECT_EQ(0, -homa_pool_init(&self->hsk.buffer_pool, &self->homa,
			(char *) 0x1000000, 100*HOMA_BPAGE_SIZE));
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_MSG,
			self->client_ip, self->server_ip, self->server_port,
			self->client_id, 100, 2000);
	EXPECT_NE(NULL, crpc);
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
	mock_copy_to_user_errors = 1;

	EXPECT_EQ(EFAULT, -homa_recvmsg(&self->hsk.inet.sk, &self->recvmsg_hdr,
			0, 0, 0, &self->recvmsg_hdr.msg_namelen));
	EXPECT_EQ(0, self->recvmsg_args.id);
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
}
TEST_F(homa_plumbing, homa_recvmsg__copy_back_args_even_after_error)
{
	EXPECT_EQ(0, -homa_pool_init(&self->hsk.buffer_pool, &self->homa,
			(char *) 0x1000000, 100*HOMA_BPAGE_SIZE));
	EXPECT_EQ(0, -homa_pool_get_pages(&self->hsk.buffer_pool, 2,
			self->recvmsg_args.bpage_offsets, 0));
	EXPECT_EQ(1, atomic_read(&self->hsk.buffer_pool.descriptors[0].refs));
	EXPECT_EQ(1, atomic_read(&self->hsk.buffer_pool.descriptors[1].refs));
	self->recvmsg_args.num_bpages = 2;
	self->recvmsg_args.bpage_offsets[0] = 0;
	self->recvmsg_args.bpage_offsets[1] = HOMA_BPAGE_SIZE;

	EXPECT_EQ(EAGAIN, -homa_recvmsg(&self->hsk.inet.sk, &self->recvmsg_hdr,
			0, 0, 0, &self->recvmsg_hdr.msg_namelen));
	EXPECT_EQ(0, self->recvmsg_args.num_bpages);
}

TEST_F(homa_plumbing, homa_softirq__basics)
{
	struct sk_buff *skb;
	skb = mock_skb_new(self->client_ip, &self->data.common, 1400, 1400);
	homa_softirq(skb);
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
}
TEST_F(homa_plumbing, homa_softirq__reorder_incoming_packets)
{
	struct sk_buff *skb, *skb2, *skb3, *skb4;

	self->data.common.sender_id = cpu_to_be64(2000);
	self->data.message_length = htonl(2000);
	skb = mock_skb_new(self->client_ip, &self->data.common, 1400, 0);
	self->data.common.sender_id = cpu_to_be64(200);
	self->data.message_length = htonl(200);
	skb2 = mock_skb_new(self->client_ip, &self->data.common, 200, 0);
	self->data.common.sender_id = cpu_to_be64(300);
	self->data.message_length = htonl(300);
	skb3 = mock_skb_new(self->client_ip, &self->data.common, 300, 0);
	self->data.common.sender_id = cpu_to_be64(5000);
	self->data.message_length = htonl(5000);
	skb4 = mock_skb_new(self->client_ip, &self->data.common, 1400, 0);
	skb_shinfo(skb)->frag_list = skb2;
	skb2->next = skb3;
	skb3->next = skb4;
	skb4->next = NULL;
	homa_softirq(skb);
	unit_log_clear();
	unit_log_active_ids(&self->hsk);
	EXPECT_STREQ("201 301 2001 5001", unit_log_get());
}
TEST_F(homa_plumbing, homa_softirq__reorder_short_packet_at_front)
{
	struct sk_buff *skb, *skb2, *skb3, *skb4;

	self->data.common.sender_id = cpu_to_be64(200);
	self->data.message_length = htonl(200);
	skb = mock_skb_new(self->client_ip, &self->data.common, 200, 0);
	self->data.common.sender_id = cpu_to_be64(4000);
	self->data.message_length = htonl(4000);
	skb2 = mock_skb_new(self->client_ip, &self->data.common, 1400, 0);
	self->data.common.sender_id = cpu_to_be64(300);
	self->data.message_length = htonl(300);
	skb3 = mock_skb_new(self->client_ip, &self->data.common, 300, 0);
	self->data.common.sender_id = cpu_to_be64(5000);
	self->data.message_length = htonl(5000);
	skb4 = mock_skb_new(self->client_ip, &self->data.common, 1400, 0);
	skb_shinfo(skb)->frag_list = skb2;
	skb2->next = skb3;
	skb3->next = skb4;
	skb4->next = NULL;
	homa_softirq(skb);
	unit_log_clear();
	unit_log_active_ids(&self->hsk);
	EXPECT_STREQ("201 301 4001 5001", unit_log_get());
}
TEST_F(homa_plumbing, homa_softirq__nothing_to_reorder)
{
	struct sk_buff *skb, *skb2, *skb3;

	self->data.common.sender_id = cpu_to_be64(2000);
	self->data.message_length = htonl(2000);
	skb = mock_skb_new(self->client_ip, &self->data.common, 1400, 0);
	self->data.common.sender_id = cpu_to_be64(3000);
	self->data.message_length = htonl(3000);
	skb2 = mock_skb_new(self->client_ip, &self->data.common, 1400, 0);
	self->data.common.sender_id = cpu_to_be64(5000);
	self->data.message_length = htonl(5000);
	skb3 = mock_skb_new(self->client_ip, &self->data.common, 1400, 0);
	skb_shinfo(skb)->frag_list = skb2;
	skb2->next = skb3;
	skb3->next = NULL;
	homa_softirq(skb);
	unit_log_clear();
	unit_log_active_ids(&self->hsk);
	EXPECT_STREQ("2001 3001 5001", unit_log_get());
}
TEST_F(homa_plumbing, homa_softirq__cant_pull_header)
{
	struct sk_buff *skb;
	skb = mock_skb_new(self->client_ip, &self->data.common, 1400, 1400);
	skb->data_len = skb->len - 20;
	homa_softirq(skb);
	EXPECT_STREQ("pskb discard", unit_log_get());
}
TEST_F(homa_plumbing, homa_softirq__remove_extra_headers)
{
	struct sk_buff *skb;
	skb = mock_skb_new(self->client_ip, &self->data.common, 1400, 1400);
	__skb_push(skb, 10);
	homa_softirq(skb);
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
}
TEST_F(homa_plumbing, homa_softirq__packet_too_short)
{
	struct sk_buff *skb;
	struct ack_header h;
	h.common.type = ACK;
	skb = mock_skb_new(self->client_ip, &h.common, 0, 0);
	skb->len -= 1;
	homa_softirq(skb);
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_EQ(1, homa_cores[cpu_number]->metrics.short_packets);
}
TEST_F(homa_plumbing, homa_softirq__bogus_packet_type)
{
	struct sk_buff *skb;
	self->data.common.type = BOGUS;
	skb = mock_skb_new(self->client_ip, &self->data.common, 1400, 1400);
	homa_softirq(skb);
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_EQ(1, homa_cores[cpu_number]->metrics.short_packets);
}
TEST_F(homa_plumbing, homa_softirq__unknown_socket_ipv4)
{
	struct sk_buff *skb;
	self->data.common.dport = htons(100);

	// Make sure the test uses IPv4.
	mock_ipv6 = false;
	homa_sock_destroy(&self->hsk);
	mock_sock_init(&self->hsk, &self->homa, 0);

	skb = mock_skb_new(self->client_ip, &self->data.common, 1400, 1400);
	homa_softirq(skb);
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_STREQ("icmp_send type 3, code 3", unit_log_get());
}
TEST_F(homa_plumbing, homa_softirq__unknown_socket_ipv6)
{
	struct sk_buff *skb;
	self->data.common.dport = htons(100);

	// Make sure the test uses IPv6.
	mock_ipv6 = true;
	homa_sock_destroy(&self->hsk);
	mock_sock_init(&self->hsk, &self->homa, 0);

	skb = mock_skb_new(self->client_ip, &self->data.common, 1400, 1400);
	homa_softirq(skb);
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_STREQ("icmp6_send type 1, code 4", unit_log_get());
}
TEST_F(homa_plumbing, homa_softirq__multiple_packets_different_sockets)
{
	struct sk_buff *skb, *skb2;
	struct homa_sock sock2;
	mock_sock_init(&sock2, &self->homa, 0);
	homa_sock_bind(&self->homa.port_map, &sock2, self->server_port+1);

	skb = mock_skb_new(self->client_ip, &self->data.common, 1400, 1400);
	self->data.common.sender_id += 2;
	self->data.common.dport = htons(self->server_port+1);
	skb2 = mock_skb_new(self->client_ip, &self->data.common, 1400, 1400);
	skb_shinfo(skb)->frag_list = skb2;
	skb2->next = NULL;
	homa_softirq(skb);
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_EQ(1, unit_list_length(&sock2.active_rpcs));
	homa_sock_destroy(&sock2);
}
TEST_F(homa_plumbing, homa_softirq__multiple_packets_same_socket)
{
	struct sk_buff *skb, *skb2;
	skb = mock_skb_new(self->client_ip, &self->data.common, 1400, 1400);
	self->data.common.sender_id += cpu_to_be64(self->client_id + 2);
	skb2 = mock_skb_new(self->client_ip, &self->data.common, 1400, 1400);
	skb_shinfo(skb)->frag_list = skb2;
	skb2->next = NULL;
	homa_softirq(skb);
	EXPECT_EQ(2, unit_list_length(&self->hsk.active_rpcs));
}
TEST_F(homa_plumbing, homa_softirq__update_total_incoming)
{
	struct sk_buff *skb, *skb2;

	self->data.seg.segment_length = htonl(1400);
	skb = mock_skb_new(self->client_ip, &self->data.common, 1400, 0);
	self->data.seg.offset = htonl(1400);
	skb2 = mock_skb_new(self->client_ip, &self->data.common, 1400, 1400);
	skb_shinfo(skb2)->frag_list = skb;
	skb->next = NULL;
	homa_softirq(skb2);
	unit_log_clear();
	unit_log_active_ids(&self->hsk);
	EXPECT_STREQ("1235", unit_log_get());
	EXPECT_EQ(7200, atomic_read(&self->homa.total_incoming));
}

TEST_F(homa_plumbing, homa_metrics_open)
{
	EXPECT_EQ(0, homa_metrics_open(NULL, NULL));
	EXPECT_NE(NULL, self->homa.metrics);

	strcpy(self->homa.metrics, "12345");
	EXPECT_EQ(0, homa_metrics_open(NULL, NULL));
	EXPECT_EQ(5, strlen(self->homa.metrics));
	EXPECT_EQ(2, self->homa.metrics_active_opens);
}
TEST_F(homa_plumbing, homa_metrics_read__basics)
{
	char buffer[1000];
	loff_t offset = 10;
	self->homa.metrics = kmalloc(100, GFP_KERNEL);
	self->homa.metrics_capacity = 100;
	strcpy(self->homa.metrics, "0123456789abcdefghijklmnop");
	self->homa.metrics_length = 26;
	EXPECT_EQ(5, homa_metrics_read(NULL, buffer, 5, &offset));
	EXPECT_SUBSTR("_copy_to_user copied 5 bytes", unit_log_get());
	EXPECT_EQ(15, offset);

	unit_log_clear();
	EXPECT_EQ(11, homa_metrics_read(NULL, buffer, 1000, &offset));
	EXPECT_SUBSTR("_copy_to_user copied 11 bytes", unit_log_get());
	EXPECT_EQ(26, offset);

	unit_log_clear();
	EXPECT_EQ(0, homa_metrics_read(NULL, buffer, 1000, &offset));
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(26, offset);
}
TEST_F(homa_plumbing, homa_metrics_read__error_copying_to_user)
{
	char buffer[1000];
	loff_t offset = 10;
	self->homa.metrics = kmalloc(100, GFP_KERNEL);
	self->homa.metrics_capacity = 100;
	strcpy(self->homa.metrics, "0123456789abcdefghijklmnop");
	self->homa.metrics_length = 26;
	mock_copy_to_user_errors = 1;
	EXPECT_EQ(EFAULT, -homa_metrics_read(NULL, buffer, 5, &offset));
}

TEST_F(homa_plumbing, homa_metrics_release)
{
	self->homa.metrics_active_opens = 2;
	EXPECT_EQ(0, homa_metrics_release(NULL, NULL));
	EXPECT_EQ(1, self->homa.metrics_active_opens);

	EXPECT_EQ(0, homa_metrics_release(NULL, NULL));
	EXPECT_EQ(0, self->homa.metrics_active_opens);
}
