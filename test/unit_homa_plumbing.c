// SPDX-License-Identifier: BSD-2-Clause

#include "homa_impl.h"
#include "homa_peer.h"
#include "homa_pool.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

/* The following hook function frees hook_rpc. */
static struct homa_rpc *hook_rpc;
static void unlock_hook(char *id)
{
	if (strcmp(id, "unlock") != 0)
		return;
	if (hook_rpc) {
		homa_rpc_end(hook_rpc);
		hook_rpc = 0;
	}
}

FIXTURE(homa_plumbing) {
	struct in6_addr client_ip[1];
	int client_port;
	struct in6_addr server_ip[1];
	int server_port;
	u64 client_id;
	u64 server_id;
	struct homa homa;
	struct homa_sock hsk;
	union sockaddr_in_union client_addr;
	union sockaddr_in_union server_addr;
	struct homa_data_hdr data;
	int starting_skb_count;
	struct msghdr recvmsg_hdr;
	struct homa_recvmsg_args recvmsg_args;
	struct iovec send_vec[2];
	struct msghdr sendmsg_hdr;
	struct homa_sendmsg_args sendmsg_args;
	char buffer[2000];
	sockptr_t optval;
	union sockaddr_in_union addr;
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
	homa_init(&self->homa, &mock_net);
	if (self->homa.wmem_max == 0)
		printf("homa_plumbing fixture found wmem_max 0\n");
	mock_set_homa(&self->homa);
	mock_sock_init(&self->hsk, &self->homa, 0);
	self->client_addr.in6.sin6_family = self->hsk.inet.sk.sk_family;
	self->server_addr.in6.sin6_family = self->hsk.inet.sk.sk_family;
	if (self->hsk.inet.sk.sk_family == AF_INET) {
		self->client_addr.in4.sin_addr.s_addr =
			ipv6_to_ipv4(self->client_addr.in6.sin6_addr);
		self->server_addr.in4.sin_addr.s_addr =
			ipv6_to_ipv4(self->server_addr.in6.sin6_addr);
	}
	homa_sock_bind(self->homa.port_map, &self->hsk, self->server_port);
	memset(&self->data, 0, sizeof(self->data));
	self->data = (struct homa_data_hdr){.common = {
		.sport = htons(self->client_port),
		.dport = htons(self->server_port),
		.type = DATA,
		.sender_id = cpu_to_be64(self->client_id)},
		.message_length = htonl(10000),
#ifndef __STRIP__ /* See strip.py */
		.incoming = htonl(10000),
#endif /* See strip.py */
	};
	self->recvmsg_args.id = 0;
	self->recvmsg_hdr.msg_name = &self->addr;
	self->recvmsg_hdr.msg_namelen = 0;
	self->recvmsg_hdr.msg_control = &self->recvmsg_args;
	self->recvmsg_hdr.msg_controllen = sizeof(self->recvmsg_args);
	self->recvmsg_hdr.msg_flags = 0;
	memset(&self->recvmsg_args, 0, sizeof(self->recvmsg_args));
	self->recvmsg_args.flags = HOMA_RECVMSG_NONBLOCKING;
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
	if (self->homa.wmem_max == 0)
		printf("homa_plumbing fixture set wmem_max 0\n");
}
FIXTURE_TEARDOWN(homa_plumbing)
{
	homa_destroy(&self->homa);
	unit_teardown();
}

TEST_F(homa_plumbing, homa_load__error_in_inet6_register_protosw)
{
	homa_destroy(&self->homa);

	/* First attempt fails. */
	mock_register_protosw_errors = 1;
	EXPECT_EQ(EINVAL, -homa_load());

	/* Second attempt succeeds. */
	EXPECT_EQ(0, -homa_load());

	homa_unload();
}

TEST_F(homa_plumbing, homa_bind__version_mismatch)
{
	struct sockaddr addr = {};
	struct socket sock = {};
	int result;

	// Make sure the test uses IPv4.
	mock_ipv6 = false;
	homa_sock_destroy(&self->hsk);
	mock_sock_init(&self->hsk, &self->homa, 0);
	addr.sa_family = AF_INET6;
	sock.sk = &self->hsk.inet.sk;
	result = homa_bind(&sock, &addr, sizeof(addr));
	EXPECT_EQ(EAFNOSUPPORT, -result);
}
TEST_F(homa_plumbing, homa_bind__ipv6_address_too_short)
{
	union sockaddr_in_union addr = {};
	struct socket sock = {};
	int result;

	// Make sure the test uses IPv6.
	mock_ipv6 = true;
	homa_sock_destroy(&self->hsk);
	mock_sock_init(&self->hsk, &self->homa, 0);

	addr.in6.sin6_family = AF_INET6;
	sock.sk = &self->hsk.inet.sk;
	result = homa_bind(&sock, &addr.sa, sizeof(addr.in6)-1);
	EXPECT_EQ(EINVAL, -result);
}
TEST_F(homa_plumbing, homa_bind__ipv6_ok)
{
	union sockaddr_in_union addr = {};
	struct socket sock = {};
	int result;

	// Make sure the test uses IPv6.
	mock_ipv6 = true;
	homa_sock_destroy(&self->hsk);
	mock_sock_init(&self->hsk, &self->homa, 0);
	self->hsk.is_server = false;

	addr.in6.sin6_family = AF_INET6;
	addr.in6.sin6_port = htons(123);
	sock.sk = &self->hsk.inet.sk;
	result = homa_bind(&sock, &addr.sa, sizeof(addr.in6));
	EXPECT_EQ(0, -result);
	EXPECT_EQ(123, self->hsk.port);
	EXPECT_EQ(1, self->hsk.is_server);
}
TEST_F(homa_plumbing, homa_bind__ipv4_address_too_short)
{
	union sockaddr_in_union addr = {};
	struct socket sock = {};
	int result;

	// Make sure the test uses IPv4.
	mock_ipv6 = false;
	homa_sock_destroy(&self->hsk);
	mock_sock_init(&self->hsk, &self->homa, 0);

	addr.in4.sin_family = AF_INET;
	sock.sk = &self->hsk.inet.sk;
	result = homa_bind(&sock, &addr.sa, sizeof(addr.in4)-1);
	EXPECT_EQ(EINVAL, -result);
}
TEST_F(homa_plumbing, homa_bind__ipv4_ok)
{
	union sockaddr_in_union addr = {};
	struct socket sock = {};
	int result;

	// Make sure the test uses IPv4.
	mock_ipv6 = false;
	homa_sock_destroy(&self->hsk);
	mock_sock_init(&self->hsk, &self->homa, 0);
	self->hsk.is_server = false;

	addr.in4.sin_family = AF_INET;
	addr.in4.sin_port = htons(345);
	sock.sk = &self->hsk.inet.sk;
	result = homa_bind(&sock, &addr.sa, sizeof(addr.in4));
	EXPECT_EQ(0, -result);
	EXPECT_EQ(345, self->hsk.port);
	EXPECT_EQ(1, self->hsk.is_server);
}

#ifndef __STRIP__ /* See strip.py */
TEST_F(homa_plumbing, homa_ioc_abort__basics)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 10000, 200);
	struct homa_abort_args args = {self->client_id, 0};

	ASSERT_NE(NULL, crpc);
	EXPECT_EQ(0, homa_ioc_abort(&self->hsk.inet.sk, (int *) &args));
	EXPECT_EQ(RPC_DEAD, crpc->state);
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
}
TEST_F(homa_plumbing, homa_ioc_abort__cant_read_user_args)
{
	struct homa_abort_args args = {self->client_id, 0};

	mock_copy_data_errors = 1;
	EXPECT_EQ(EFAULT, -homa_ioc_abort(&self->hsk.inet.sk, (int *) &args));
}
TEST_F(homa_plumbing, homa_ioc_abort__abort_multiple_rpcs)
{
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 10000, 200);
	struct homa_rpc *crpc2 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 10000, 200);
	struct homa_abort_args args = {0, ECANCELED};

	ASSERT_NE(NULL, crpc1);
	ASSERT_NE(NULL, crpc2);
	EXPECT_EQ(0, homa_ioc_abort(&self->hsk.inet.sk, (int *) &args));
	EXPECT_EQ(-ECANCELED, crpc1->error);
	EXPECT_EQ(-ECANCELED, crpc2->error);
	EXPECT_EQ(2, unit_list_length(&self->hsk.active_rpcs));
}
TEST_F(homa_plumbing, homa_ioc_abort__nonexistent_rpc)
{
	struct homa_abort_args args = {99, 0};

	EXPECT_EQ(EINVAL, -homa_ioc_abort(&self->hsk.inet.sk, (int *) &args));
}
#endif /* See strip.py */

TEST_F(homa_plumbing, homa_socket__success)
{
	struct homa_sock hsk;

	memset(&hsk, 0, sizeof(hsk));
	hsk.sock.sk_net.net = &mock_net;
	refcount_set(&hsk.sock.sk_wmem_alloc, 1);
	EXPECT_EQ(0, homa_socket(&hsk.sock));
	homa_sock_destroy(&hsk);
}
TEST_F(homa_plumbing, homa_socket__homa_sock_init_failure)
{
	struct homa_sock hsk;

	memset(&hsk, 0, sizeof(hsk));
	hsk.sock.sk_net.net = &mock_net;
	refcount_set(&hsk.sock.sk_wmem_alloc, 1);
	mock_kmalloc_errors = 1;
	EXPECT_EQ(ENOMEM, -homa_socket(&hsk.sock));
}

TEST_F(homa_plumbing, homa_setsockopt__bad_level)
{
	EXPECT_EQ(ENOPROTOOPT, -homa_setsockopt(&self->hsk.sock, 0, 0,
		self->optval, sizeof(struct homa_rcvbuf_args)));
}
TEST_F(homa_plumbing, homa_setsockopt__bad_optname)
{
	EXPECT_EQ(ENOPROTOOPT, -homa_setsockopt(&self->hsk.sock, IPPROTO_HOMA, 0,
		self->optval, sizeof(struct homa_rcvbuf_args)));
}
TEST_F(homa_plumbing, homa_setsockopt__recvbuf_bad_optlen)
{
	EXPECT_EQ(EINVAL, -homa_setsockopt(&self->hsk.sock, IPPROTO_HOMA,
			SO_HOMA_RCVBUF, self->optval,
			sizeof(struct homa_rcvbuf_args) - 1));
}
TEST_F(homa_plumbing, homa_setsockopt__recvbuf_copy_from_sockptr_fails)
{
	mock_copy_data_errors = 1;
	EXPECT_EQ(EFAULT, -homa_setsockopt(&self->hsk.sock, IPPROTO_HOMA,
			SO_HOMA_RCVBUF, self->optval,
			sizeof(struct homa_rcvbuf_args)));
}
TEST_F(homa_plumbing, homa_setsockopt__recvbuf_copy_to_user_fails)
{
	struct homa_rcvbuf_args args = {0x100000, 5*HOMA_BPAGE_SIZE};

	self->optval.user = &args;
	mock_copy_to_user_errors = 1;
	EXPECT_EQ(EFAULT, -homa_setsockopt(&self->hsk.sock, IPPROTO_HOMA,
			SO_HOMA_RCVBUF, self->optval,
			sizeof(struct homa_rcvbuf_args)));
}
TEST_F(homa_plumbing, homa_setsockopt__recvbuf_success)
{
	struct homa_rcvbuf_args args;
	char buffer[5000];

	args.start = (((uintptr_t)(buffer + PAGE_SIZE - 1))
			& ~(PAGE_SIZE - 1));
	args.length = 64*HOMA_BPAGE_SIZE;
	self->optval.user = &args;
	homa_pool_destroy(self->hsk.buffer_pool);
	EXPECT_EQ(0, -homa_setsockopt(&self->hsk.sock, IPPROTO_HOMA,
			SO_HOMA_RCVBUF, self->optval,
			sizeof(struct homa_rcvbuf_args)));
	EXPECT_EQ(args.start, (uintptr_t)self->hsk.buffer_pool->region);
	EXPECT_EQ(64, self->hsk.buffer_pool->num_bpages);
#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(1, homa_metrics_per_cpu()->so_set_buf_calls);
#endif /* See strip.py */
}
TEST_F(homa_plumbing, homa_setsockopt__server_bad_optlen)
{
	EXPECT_EQ(EINVAL, -homa_setsockopt(&self->hsk.sock, IPPROTO_HOMA,
			SO_HOMA_SERVER, self->optval, sizeof(int) - 1));
}
TEST_F(homa_plumbing, homa_setsockopt__server_copy_from_sockptr_fails)
{
	mock_copy_data_errors = 1;
	EXPECT_EQ(EFAULT, -homa_setsockopt(&self->hsk.sock, IPPROTO_HOMA,
			SO_HOMA_SERVER, self->optval, sizeof(int)));
}
TEST_F(homa_plumbing, homa_setsockopt__server_success)
{
	int arg = 7;

	self->optval.user = &arg;
	EXPECT_EQ(0, -homa_setsockopt(&self->hsk.sock, IPPROTO_HOMA,
			SO_HOMA_SERVER, self->optval, sizeof(int)));
	EXPECT_EQ(1, self->hsk.is_server);

	arg = 0;
	EXPECT_EQ(0, -homa_setsockopt(&self->hsk.sock, IPPROTO_HOMA,
			SO_HOMA_SERVER, self->optval, sizeof(int)));
	EXPECT_EQ(0, self->hsk.is_server);
}


TEST_F(homa_plumbing, homa_getsockopt__recvbuf_success)
{
	struct homa_rcvbuf_args val;
	int size = sizeof32(val) + 10;

	EXPECT_EQ(0, -homa_pool_init(&self->hsk, (void *)0x40000,
		  10*HOMA_BPAGE_SIZE + 1000));
	EXPECT_EQ(0, -homa_getsockopt(&self->hsk.sock, IPPROTO_HOMA,
		  SO_HOMA_RCVBUF, (char *)&val, &size));
	EXPECT_EQ(0x40000, val.start);
	EXPECT_EQ(10*HOMA_BPAGE_SIZE, val.length);
	EXPECT_EQ(sizeof32(val), size);
}
TEST_F(homa_plumbing, homa_getsockopt__cant_read_size)
{
	struct homa_rcvbuf_args val;
	int size = sizeof32(val);

	mock_copy_data_errors = 1;
	EXPECT_EQ(EFAULT, -homa_getsockopt(&self->hsk.sock, 0, SO_HOMA_RCVBUF,
		(char *)&val, &size));
}
TEST_F(homa_plumbing, homa_getsockopt__bad_level)
{
	struct homa_rcvbuf_args val;
	int size = sizeof32(val);

	EXPECT_EQ(ENOPROTOOPT, -homa_getsockopt(&self->hsk.sock, 0, SO_HOMA_RCVBUF,
		(char *)&val, &size));
}
TEST_F(homa_plumbing, homa_getsockopt__recvbuf_bad_length)
{
	struct homa_rcvbuf_args val;
	int size = sizeof32(val) - 1;

	EXPECT_EQ(EINVAL, -homa_getsockopt(&self->hsk.sock, IPPROTO_HOMA,
		  SO_HOMA_RCVBUF, (char *)&val, &size));
}
TEST_F(homa_plumbing, homa_getsockopt__server_bad_length)
{
	int is_server;
	int size = sizeof32(is_server) - 1;

	EXPECT_EQ(EINVAL, -homa_getsockopt(&self->hsk.sock, IPPROTO_HOMA,
		  SO_HOMA_SERVER, (char *)&is_server, &size));
}
TEST_F(homa_plumbing, homa_getsockopt__server_success)
{
	int is_server;
	int size = sizeof32(is_server);

	self->hsk.is_server = 1;
	EXPECT_EQ(0, -homa_getsockopt(&self->hsk.sock, IPPROTO_HOMA,
		  SO_HOMA_SERVER, (char *)&is_server, &size));
	EXPECT_EQ(1, is_server);
	EXPECT_EQ(sizeof(int), size);

	self->hsk.is_server = 0;
	size = 20;
	EXPECT_EQ(0, -homa_getsockopt(&self->hsk.sock, IPPROTO_HOMA,
		  SO_HOMA_SERVER, (char *)&is_server, &size));
	EXPECT_EQ(0, is_server);
	EXPECT_EQ(sizeof(int), size);
}
TEST_F(homa_plumbing, homa_getsockopt__bad_optname)
{
	struct homa_rcvbuf_args val;
	int size = sizeof32(val);

	EXPECT_EQ(ENOPROTOOPT, -homa_getsockopt(&self->hsk.sock, IPPROTO_HOMA,
		  SO_HOMA_RCVBUF-1, (char *)&val, &size));
}
TEST_F(homa_plumbing, homa_getsockopt__cant_copy_out_size)
{
	struct homa_rcvbuf_args val = {.start = 0, .length = 0};
	int size = sizeof32(val) + 10;

	EXPECT_EQ(0, -homa_pool_init(&self->hsk, (void *)0x40000,
		  10*HOMA_BPAGE_SIZE + 1000));
	mock_copy_to_user_errors = 1;

	EXPECT_EQ(EFAULT, -homa_getsockopt(&self->hsk.sock, IPPROTO_HOMA,
		  SO_HOMA_RCVBUF, (char *)&val, &size));
	EXPECT_EQ(0, val.start);
	EXPECT_EQ(sizeof32(val) + 10, size);
}
TEST_F(homa_plumbing, homa_getsockopt__cant_copy_out_value)
{
	struct homa_rcvbuf_args val = {.start = 0, .length = 0};
	int size = sizeof32(val) + 10;

	EXPECT_EQ(0, -homa_pool_init(&self->hsk, (void *)0x40000,
		  10*HOMA_BPAGE_SIZE + 1000));
	mock_copy_to_user_errors = 2;

	EXPECT_EQ(EFAULT, -homa_getsockopt(&self->hsk.sock, IPPROTO_HOMA,
		  SO_HOMA_RCVBUF, (char *)&val, &size));
	EXPECT_EQ(0, val.start);
	EXPECT_EQ(sizeof32(val), size);
}

TEST_F(homa_plumbing, homa_sendmsg__msg_name_null)
{
	self->sendmsg_hdr.msg_name = NULL;
	EXPECT_EQ(EINVAL, -homa_sendmsg(&self->hsk.inet.sk,
		&self->sendmsg_hdr, self->sendmsg_hdr.msg_iter.count));
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
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
TEST_F(homa_plumbing, homa_sendmsg__illegal_flag)
{
	self->sendmsg_args.flags = 4;
	EXPECT_EQ(EINVAL, -homa_sendmsg(&self->hsk.inet.sk,
		&self->sendmsg_hdr, self->sendmsg_hdr.msg_iter.count));
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
}
TEST_F(homa_plumbing, homa_sendmsg__nonzero_reserved_field)
{
	self->sendmsg_args.reserved = 0x1000;
	EXPECT_EQ(EINVAL, -homa_sendmsg(&self->hsk.inet.sk,
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
TEST_F(homa_plumbing, homa_sendmsg__error_in_homa_message_out_fill)
{
	self->sendmsg_hdr.msg_iter.count = HOMA_MAX_MESSAGE_LENGTH+1;
	EXPECT_EQ(EINVAL, -homa_sendmsg(&self->hsk.inet.sk,
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
TEST_F(homa_plumbing, homa_sendmsg__response_cant_find_rpc)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, UNIT_IN_SERVICE,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 2000, 100);

	self->sendmsg_args.id = self->server_id + 1;
	EXPECT_EQ(0, -homa_sendmsg(&self->hsk.inet.sk,
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
TEST_F(homa_plumbing, homa_sendmsg__homa_message_out_fill_returns_error)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, UNIT_IN_SERVICE,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 2000, 100);

	self->sendmsg_args.id = self->server_id;
	self->sendmsg_hdr.msg_iter.count = HOMA_MAX_MESSAGE_LENGTH + 1;
	EXPECT_EQ(EINVAL, -homa_sendmsg(&self->hsk.inet.sk,
		&self->sendmsg_hdr, self->sendmsg_hdr.msg_iter.count));
	EXPECT_EQ(RPC_DEAD, srpc->state);
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
}
TEST_F(homa_plumbing, homa_sendmsg__rpc_freed_during_homa_message_out_fill)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, UNIT_IN_SERVICE,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 2000, 100);

	unit_hook_register(unlock_hook);
	hook_rpc = srpc;
	self->sendmsg_args.id = self->server_id;
	EXPECT_EQ(0, -homa_sendmsg(&self->hsk.inet.sk,
		&self->sendmsg_hdr, self->sendmsg_hdr.msg_iter.count));
	EXPECT_EQ(RPC_DEAD, srpc->state);
	EXPECT_EQ(0, srpc->msgout.num_skbs);
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
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
			0, 0, &self->recvmsg_hdr.msg_namelen));
}
TEST_F(homa_plumbing, homa_recvmsg__cant_read_args)
{
	mock_copy_data_errors = 1;
	EXPECT_EQ(EFAULT, -homa_recvmsg(&self->hsk.inet.sk, &self->recvmsg_hdr,
			0, 0, &self->recvmsg_hdr.msg_namelen));
}
TEST_F(homa_plumbing, homa_recvmsg__clear_cookie)
{
	// Make sure that the completion_cookie will be zero if anything
	// goes wrong with the receive.
	self->recvmsg_args.completion_cookie = 12345;
	self->recvmsg_args.num_bpages = 1000000;
	EXPECT_EQ(EINVAL, -homa_recvmsg(&self->hsk.inet.sk, &self->recvmsg_hdr,
			0, 0, &self->recvmsg_hdr.msg_namelen));
	EXPECT_EQ(0, self->recvmsg_args.completion_cookie);
}
TEST_F(homa_plumbing, homa_recvmsg__num_bpages_too_large)
{
	self->recvmsg_args.num_bpages = HOMA_MAX_BPAGES + 1;
	EXPECT_EQ(EINVAL, -homa_recvmsg(&self->hsk.inet.sk, &self->recvmsg_hdr,
			0, 0, &self->recvmsg_hdr.msg_namelen));
}
TEST_F(homa_plumbing, homa_recvmsg__bogus_flags)
{
	self->recvmsg_args.flags = 1 << 10;
	EXPECT_EQ(EINVAL, -homa_recvmsg(&self->hsk.inet.sk, &self->recvmsg_hdr,
			0, 0, &self->recvmsg_hdr.msg_namelen));
}
TEST_F(homa_plumbing, homa_recvmsg__no_buffer_pool)
{
	struct homa_pool *saved_pool = self->hsk.buffer_pool;

	self->hsk.buffer_pool = NULL;
	EXPECT_EQ(EINVAL, -homa_recvmsg(&self->hsk.inet.sk, &self->recvmsg_hdr,
			0, 0, &self->recvmsg_hdr.msg_namelen));
	self->hsk.buffer_pool = saved_pool;
}
TEST_F(homa_plumbing, homa_recvmsg__release_buffers)
{
	EXPECT_EQ(0, -homa_pool_get_pages(self->hsk.buffer_pool, 2,
			self->recvmsg_args.bpage_offsets, 0));
	EXPECT_EQ(1, atomic_read(&self->hsk.buffer_pool->descriptors[0].refs));
	EXPECT_EQ(1, atomic_read(&self->hsk.buffer_pool->descriptors[1].refs));
	self->recvmsg_args.num_bpages = 2;
	self->recvmsg_args.bpage_offsets[0] = 0;
	self->recvmsg_args.bpage_offsets[1] = HOMA_BPAGE_SIZE;

	EXPECT_EQ(EAGAIN, -homa_recvmsg(&self->hsk.inet.sk, &self->recvmsg_hdr,
			0, 0, &self->recvmsg_hdr.msg_namelen));
	EXPECT_EQ(0, atomic_read(&self->hsk.buffer_pool->descriptors[0].refs));
	EXPECT_EQ(0, atomic_read(&self->hsk.buffer_pool->descriptors[1].refs));
}
TEST_F(homa_plumbing, homa_recvmsg__error_in_release_buffers)
{
	self->recvmsg_args.num_bpages = 1;
	self->recvmsg_args.bpage_offsets[0] =
			self->hsk.buffer_pool->num_bpages << HOMA_BPAGE_SHIFT;

	EXPECT_EQ(EINVAL, -homa_recvmsg(&self->hsk.inet.sk, &self->recvmsg_hdr,
			0, 0, &self->recvmsg_hdr.msg_namelen));
}
TEST_F(homa_plumbing, homa_recvmsg__private_rpc_doesnt_exist)
{
	self->recvmsg_args.id = 99;

	EXPECT_EQ(EINVAL, -homa_recvmsg(&self->hsk.inet.sk, &self->recvmsg_hdr,
			0, 0, &self->recvmsg_hdr.msg_namelen));
}
TEST_F(homa_plumbing, homa_recvmsg__error_from_homa_wait_private)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->server_port,
			self->client_id, 100, 2000);

	EXPECT_NE(NULL, crpc);
	atomic_or(RPC_PRIVATE, &crpc->flags);

	self->recvmsg_args.id = crpc->id;
	self->recvmsg_args.flags = HOMA_RECVMSG_NONBLOCKING;

	EXPECT_EQ(EAGAIN, -homa_recvmsg(&self->hsk.inet.sk, &self->recvmsg_hdr,
			0, 0, &self->recvmsg_hdr.msg_namelen));
	EXPECT_EQ(0, self->recvmsg_args.id);
}
TEST_F(homa_plumbing, homa_recvmsg__error_from_homa_wait_shared)
{
	self->recvmsg_args.flags = HOMA_RECVMSG_NONBLOCKING;

	EXPECT_EQ(EAGAIN, -homa_recvmsg(&self->hsk.inet.sk, &self->recvmsg_hdr,
			0, 0, &self->recvmsg_hdr.msg_namelen));
}
TEST_F(homa_plumbing, homa_recvmsg__MSG_DONT_WAIT)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->server_port,
			self->client_id, 100, 2000);

	EXPECT_NE(NULL, crpc);

	EXPECT_EQ(EAGAIN, -homa_recvmsg(&self->hsk.inet.sk,
			&self->recvmsg_hdr, 0, MSG_DONTWAIT,
			&self->recvmsg_hdr.msg_namelen));
}
TEST_F(homa_plumbing, homa_recvmsg__normal_completion_ipv4)
{
	struct homa_rpc *crpc;
	u32 pages[2];

	// Make sure the test uses IPv4.
	mock_ipv6 = false;
	homa_sock_destroy(&self->hsk);
	mock_sock_init(&self->hsk, &self->homa, 0);

	EXPECT_EQ(0, -homa_pool_get_pages(self->hsk.buffer_pool, 2, pages, 0));
	crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_MSG, self->client_ip,
			self->server_ip, self->server_port, self->client_id,
			100, 2000);
	EXPECT_NE(NULL, crpc);
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
	crpc->completion_cookie = 44444;

	EXPECT_EQ(2000, homa_recvmsg(&self->hsk.inet.sk, &self->recvmsg_hdr,
			0, 0, &self->recvmsg_hdr.msg_namelen));
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
}
TEST_F(homa_plumbing, homa_recvmsg__normal_completion_ipv6)
{
	struct in6_addr server_ip6;
	struct homa_rpc *crpc;

	// Make sure the test uses IPv6.
	mock_ipv6 = true;
	homa_sock_destroy(&self->hsk);
	mock_sock_init(&self->hsk, &self->homa, 0);
	server_ip6 = unit_get_in_addr("1::3:5:7");

	crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_MSG, self->client_ip,
			&server_ip6, self->server_port, self->client_id,
			100, 2000);
	EXPECT_NE(NULL, crpc);
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
	crpc->completion_cookie = 44444;

	EXPECT_EQ(2000, homa_recvmsg(&self->hsk.inet.sk, &self->recvmsg_hdr,
			0, 0, &self->recvmsg_hdr.msg_namelen));
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
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->server_port,
			self->client_id, 100, 2000);

	mock_set_ipv6(&self->hsk);
	EXPECT_NE(NULL, crpc);
	crpc->completion_cookie = 44444;
	homa_rpc_abort(crpc, -ETIMEDOUT);

	EXPECT_EQ(ETIMEDOUT, -homa_recvmsg(&self->hsk.inet.sk,
			&self->recvmsg_hdr, 0, 0,
			&self->recvmsg_hdr.msg_namelen));
	EXPECT_EQ(self->client_id, self->recvmsg_args.id);
	EXPECT_EQ(44444, self->recvmsg_args.completion_cookie);
	EXPECT_EQ(AF_INET6, self->addr.in6.sin6_family);
	EXPECT_STREQ("1.2.3.4", homa_print_ipv6_addr(
			&self->addr.in6.sin6_addr));
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_EQ(0, self->recvmsg_args.num_bpages);
}
TEST_F(homa_plumbing, homa_recvmsg__add_ack)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_MSG,
			self->client_ip, self->server_ip, self->server_port,
			self->client_id, 100, 2000);

	EXPECT_NE(NULL, crpc);
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
	crpc->completion_cookie = 44444;

	EXPECT_EQ(2000, homa_recvmsg(&self->hsk.inet.sk, &self->recvmsg_hdr,
			0, 0, &self->recvmsg_hdr.msg_namelen));
	EXPECT_EQ(1, crpc->peer->num_acks);
}
TEST_F(homa_plumbing, homa_recvmsg__server_normal_completion)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, UNIT_RCVD_MSG,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 100, 200);

	EXPECT_NE(NULL, srpc);
	EXPECT_EQ(100, homa_recvmsg(&self->hsk.inet.sk, &self->recvmsg_hdr,
			0, 0, &self->recvmsg_hdr.msg_namelen));
	EXPECT_EQ(self->server_id, self->recvmsg_args.id);
	EXPECT_EQ(RPC_IN_SERVICE, srpc->state);
	EXPECT_EQ(0, srpc->peer->num_acks);
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
}
TEST_F(homa_plumbing, homa_recvmsg__delete_server_rpc_after_error)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, UNIT_RCVD_MSG,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 100, 200);

	EXPECT_NE(NULL, srpc);
	srpc->error = -ENOMEM;

	EXPECT_EQ(ENOMEM, -homa_recvmsg(&self->hsk.inet.sk, &self->recvmsg_hdr,
			0, 0, &self->recvmsg_hdr.msg_namelen));
	EXPECT_EQ(self->server_id, self->recvmsg_args.id);
	EXPECT_EQ(RPC_DEAD, srpc->state);
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
}
TEST_F(homa_plumbing, homa_recvmsg__error_copying_out_args)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_MSG,
			self->client_ip, self->server_ip, self->server_port,
			self->client_id, 100, 2000);

	EXPECT_NE(NULL, crpc);
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
	mock_copy_to_user_errors = 1;

	EXPECT_EQ(EFAULT, -homa_recvmsg(&self->hsk.inet.sk, &self->recvmsg_hdr,
			0, 0, &self->recvmsg_hdr.msg_namelen));
	EXPECT_EQ(0, self->recvmsg_args.id);
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
}
TEST_F(homa_plumbing, homa_recvmsg__copy_back_args_even_after_error)
{
	EXPECT_EQ(0, -homa_pool_get_pages(self->hsk.buffer_pool, 2,
			self->recvmsg_args.bpage_offsets, 0));
	EXPECT_EQ(1, atomic_read(&self->hsk.buffer_pool->descriptors[0].refs));
	EXPECT_EQ(1, atomic_read(&self->hsk.buffer_pool->descriptors[1].refs));
	self->recvmsg_args.num_bpages = 2;
	self->recvmsg_args.bpage_offsets[0] = 0;
	self->recvmsg_args.bpage_offsets[1] = HOMA_BPAGE_SIZE;

	EXPECT_EQ(EAGAIN, -homa_recvmsg(&self->hsk.inet.sk, &self->recvmsg_hdr,
			0, 0, &self->recvmsg_hdr.msg_namelen));
	EXPECT_EQ(0, self->recvmsg_args.num_bpages);
}

TEST_F(homa_plumbing, homa_softirq__basics)
{
	struct sk_buff *skb;

	skb = mock_skb_new(self->client_ip, &self->data.common, 1400, 1400);
	homa_softirq(skb);
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
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
	struct homa_ack_hdr h;

	h.common.type = ACK;
	skb = mock_skb_new(self->client_ip, &h.common, 0, 0);
	skb->len -= 1;
	homa_softirq(skb);
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(1, homa_metrics_per_cpu()->short_packets);
#endif /* See strip.py */
}
TEST_F(homa_plumbing, homa_softirq__bogus_packet_type)
{
	struct sk_buff *skb;

	self->data.common.type = BOGUS;
	skb = mock_skb_new(self->client_ip, &self->data.common, 1400, 1400);
	homa_softirq(skb);
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(1, homa_metrics_per_cpu()->short_packets);
#endif /* See strip.py */
}
TEST_F(homa_plumbing, homa_softirq__process_short_messages_first)
{
	struct sk_buff *skb, *skb2, *skb3, *skb4;

	self->data.common.sender_id = cpu_to_be64(2000);
	self->data.message_length = htonl(2000);
	skb = mock_skb_new(self->client_ip, &self->data.common, 1400, 0);
	self->data.common.sender_id = cpu_to_be64(300);
	self->data.message_length = htonl(300);
	skb2 = mock_skb_new(self->client_ip, &self->data.common, 300, 0);
	self->data.common.sender_id = cpu_to_be64(200);
	self->data.message_length = htonl(1600);
	self->data.seg.offset = htonl(1400);
	skb3 = mock_skb_new(self->client_ip, &self->data.common, 200, 0);
	self->data.common.sender_id = cpu_to_be64(5000);
	self->data.message_length = htonl(5000);
	self->data.seg.offset = 0;
	skb4 = mock_skb_new(self->client_ip, &self->data.common, 1400, 0);
	skb_shinfo(skb)->frag_list = skb2;
	skb2->next = skb3;
	skb3->next = skb4;
	skb4->next = NULL;
	homa_softirq(skb);
	unit_log_clear();
	unit_log_active_ids(&self->hsk);
	EXPECT_STREQ("301 2001 201 5001", unit_log_get());
}
TEST_F(homa_plumbing, homa_softirq__process_control_first)
{
	struct homa_common_hdr unknown = {
		.sport = htons(self->client_port),
		.dport = htons(self->server_port),
		.type = RPC_UNKNOWN,
		.sender_id = cpu_to_be64(self->client_id)
	};
	struct sk_buff *skb, *skb2;

	self->data.common.sender_id = cpu_to_be64(2000);
	self->data.message_length = htonl(2000);
	skb = mock_skb_new(self->client_ip, &self->data.common, 1400, 0);
	skb2 = mock_skb_new(self->client_ip, &unknown, 0, 0);

	skb_shinfo(skb)->frag_list = skb2;
	skb2->next = NULL;
	unit_log_clear();
	homa_softirq(skb);
	EXPECT_SUBSTR("homa_softirq shortcut type 0x13", unit_log_get());
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
TEST_F(homa_plumbing, homa_softirq__per_rpc_batching)
{
	struct sk_buff *skb, *tail;

	self->data.common.sender_id = cpu_to_be64(2000);
	self->data.message_length = htonl(10000);
	skb = mock_skb_new(self->client_ip, &self->data.common, 1400, 0);
	tail = skb;

	self->data.common.sender_id = cpu_to_be64(2002);
	tail->next = mock_skb_new(self->client_ip, &self->data.common, 1400, 0);
	tail = tail->next;

	self->data.common.sender_id = cpu_to_be64(2004);
	tail->next = mock_skb_new(self->client_ip, &self->data.common, 1400, 0);
	tail = tail->next;

	self->data.common.sender_id = cpu_to_be64(2002);
	self->data.seg.offset = htonl(1400);
	tail->next = mock_skb_new(self->client_ip, &self->data.common, 1400, 0);
	tail = tail->next;

	self->data.common.sender_id = cpu_to_be64(2004);
	tail->next = mock_skb_new(self->client_ip, &self->data.common, 1400, 0);
	tail = tail->next;

	self->data.common.sender_id = cpu_to_be64(2002);
	self->data.seg.offset = htonl(4200);
	tail->next = mock_skb_new(self->client_ip, &self->data.common, 1400, 0);
	tail = tail->next;

	self->data.common.sender_id = cpu_to_be64(2002);
	self->data.seg.offset = htonl(2800);
	tail->next = mock_skb_new(self->client_ip, &self->data.common, 1400, 0);
	tail = tail->next;

	self->data.common.sender_id = cpu_to_be64(2004);
	self->data.seg.offset = htonl(5600);
	tail->next = mock_skb_new(self->client_ip, &self->data.common, 1400, 0);
	tail = tail->next;

	self->data.common.sender_id = cpu_to_be64(2002);
	self->data.seg.offset = htonl(7000);
	tail->next = mock_skb_new(self->client_ip, &self->data.common, 1400, 0);
	tail = tail->next;

	skb_shinfo(skb)->frag_list = skb->next;
	skb->next = NULL;
	unit_log_clear();
	homa_softirq(skb);
	EXPECT_STREQ("id 2001, offsets 0; "
			"sk->sk_data_ready invoked; "
			"id 2003, offsets 0 1400 4200 2800 7000; "
			"sk->sk_data_ready invoked; "
			"id 2005, offsets 0 1400 5600; "
			"sk->sk_data_ready invoked",
			unit_log_get());
}

TEST_F(homa_plumbing, homa_err_handler_v4__port_unreachable)
{
	struct homa_rpc *crpc;
	struct icmphdr *icmph;
	struct sk_buff *icmp, *failed;

	mock_ipv6 = false;
	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			       self->server_ip, self->server_port,
			       self->client_id, 100, 100);
	ASSERT_NE(NULL, crpc);

	failed = mock_skb_new(self->server_ip, &self->data.common, 100, 0);
	ip_hdr(failed)->daddr = ipv6_to_ipv4(self->server_ip[0]);

	icmp = mock_skb_new(self->server_ip, NULL, 1000, 0);
	icmph = skb_put(icmp, sizeof *icmph);
	icmph->type = ICMP_DEST_UNREACH;
	icmph->code = ICMP_PORT_UNREACH;
	icmp->data = skb_tail_pointer(icmp);
	memcpy(skb_put(icmp, failed->len), failed->head, failed->len);

	EXPECT_EQ(0, homa_err_handler_v4(icmp, 111));
	EXPECT_EQ(ENOTCONN, -crpc->error);

	kfree_skb(icmp);
	kfree_skb(failed);
}
TEST_F(homa_plumbing, homa_err_handler_v4__host_unreachable)
{
	struct homa_rpc *crpc;
	struct icmphdr *icmph;
	struct sk_buff *icmp, *failed;

	mock_ipv6 = false;
	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			       self->server_ip, self->server_port,
			       self->client_id, 100, 100);
	ASSERT_NE(NULL, crpc);

	failed = mock_skb_new(self->server_ip, &self->data.common, 100, 0);
	ip_hdr(failed)->daddr = ipv6_to_ipv4(self->server_ip[0]);

	icmp = mock_skb_new(self->server_ip, NULL, 1000, 0);
	icmph = skb_put(icmp, sizeof *icmph);
	icmph->type = ICMP_DEST_UNREACH;
	icmph->code = ICMP_HOST_UNKNOWN;
	icmp->data = skb_tail_pointer(icmp);
	memcpy(skb_put(icmp, failed->len), failed->head, failed->len);

	EXPECT_EQ(0, homa_err_handler_v4(icmp, 111));
	EXPECT_EQ(EHOSTUNREACH, -crpc->error);

	kfree_skb(icmp);
	kfree_skb(failed);
}

TEST_F(homa_plumbing, homa_err_handler_v6__port_unreachable)
{
	struct homa_rpc *crpc;
	struct sk_buff *icmp, *failed;

	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			       self->server_ip, self->server_port,
			       self->client_id, 100, 100);
	ASSERT_NE(NULL, crpc);

	failed = mock_skb_new(self->server_ip, &self->data.common, 100, 0);
	ipv6_hdr(failed)->daddr = self->server_ip[0];

	icmp = mock_skb_new(self->server_ip, NULL, 1000, 0);
	memcpy(skb_put(icmp, failed->len), failed->head, failed->len);

	EXPECT_EQ(0, homa_err_handler_v6(icmp, NULL, ICMPV6_DEST_UNREACH,
					 ICMPV6_PORT_UNREACH, 0, 111));
	EXPECT_EQ(ENOTCONN, -crpc->error);

	kfree_skb(icmp);
	kfree_skb(failed);
}
TEST_F(homa_plumbing, homa_err_handler_v6__protocol_not_supported)
{
	struct homa_rpc *crpc;
	struct sk_buff *icmp, *failed;

	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			       self->server_ip, self->server_port,
			       self->client_id, 100, 100);
	ASSERT_NE(NULL, crpc);

	failed = mock_skb_new(self->server_ip, &self->data.common, 100, 0);
	ipv6_hdr(failed)->daddr = self->server_ip[0];

	icmp = mock_skb_new(self->server_ip, NULL, 1000, 0);
	memcpy(skb_put(icmp, failed->len), failed->head, failed->len);

	EXPECT_EQ(0, homa_err_handler_v6(icmp, NULL, ICMPV6_PARAMPROB,
					 ICMPV6_UNK_NEXTHDR, 0, 111));
	EXPECT_EQ(EPROTONOSUPPORT, -crpc->error);

	kfree_skb(icmp);
	kfree_skb(failed);
}

TEST_F(homa_plumbing, homa_poll__no_tx_buffer_space)
{
	struct socket sock = {.sk = &self->hsk.sock};

	self->hsk.sock.sk_sndbuf = 0;
	EXPECT_EQ(0, homa_poll(NULL, &sock, NULL));
	EXPECT_EQ(1, test_bit(SOCK_NOSPACE, &self->hsk.sock.sk_socket->flags));
}
TEST_F(homa_plumbing, homa_poll__not_readable)
{
	struct socket sock = {.sk = &self->hsk.sock};

	EXPECT_EQ(POLLOUT | POLLWRNORM, homa_poll(NULL, &sock, NULL));
}
TEST_F(homa_plumbing, homa_poll__socket_shutdown)
{
	struct socket sock = {.sk = &self->hsk.sock};

	homa_sock_shutdown(&self->hsk);
	EXPECT_EQ(POLLIN | POLLOUT | POLLWRNORM, homa_poll(NULL, &sock, NULL));
}
TEST_F(homa_plumbing, homa_poll__socket_readable)
{
	struct socket sock = {.sk = &self->hsk.sock};

	unit_client_rpc(&self->hsk, UNIT_RCVD_MSG, self->client_ip,
			       self->server_ip, self->server_port,
			       self->client_id, 100, 100);
	EXPECT_EQ(POLLIN | POLLRDNORM | POLLOUT | POLLWRNORM,
		  homa_poll(NULL, &sock, NULL));
}
