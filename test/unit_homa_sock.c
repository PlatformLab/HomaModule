/* Copyright (c) 2019-2022 Homa Developers
 * SPDX-License-Identifier: BSD-1-Clause
 */

#include "homa_impl.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

#define n(x) htons(x)
#define N(x) htonl(x)

FIXTURE(homa_sock) {
	struct homa homa;
	struct homa_sock hsk;
	struct in6_addr client_ip[1];
	int client_port;
	struct in6_addr server_ip[1];
	int server_port;
	__u64 client_id;
};
FIXTURE_SETUP(homa_sock)
{
	homa_init(&self->homa);
	mock_sock_init(&self->hsk, &self->homa, 0);
	self->client_ip[0] = unit_get_in_addr("196.168.0.1");
	self->client_port = 40000;
	self->server_ip[0] = unit_get_in_addr("1.2.3.4");
	self->server_port = 99;
	self->client_id = 1234;
}
FIXTURE_TEARDOWN(homa_sock)
{
	homa_destroy(&self->homa);
	unit_teardown();
}

TEST_F(homa_sock, homa_port_hash)
{
	EXPECT_EQ(1023, homa_port_hash(0xffff));
	EXPECT_EQ(18, homa_port_hash(0x6012));
	EXPECT_EQ(99, homa_port_hash(99));
}

TEST_F(homa_sock, homa_socktab_start_scan)
{
	struct homa_socktab_scan scan;
	homa_destroy(&self->homa);
	homa_init(&self->homa);
	mock_sock_init(&self->hsk, &self->homa, HOMA_MIN_DEFAULT_PORT+100);
	EXPECT_EQ(&self->hsk, homa_socktab_start_scan(&self->homa.port_map,
			&scan));
	EXPECT_EQ(100, scan.current_bucket);
}

TEST_F(homa_sock, homa_socktab_next__basics)
{
	struct homa_sock hsk1, hsk2, hsk3, hsk4, *hsk;
	struct homa_socktab_scan scan;
	int first_port = 34000;
	homa_destroy(&self->homa);
	homa_init(&self->homa);
	mock_sock_init(&hsk1, &self->homa, first_port);
	mock_sock_init(&hsk2, &self->homa, first_port+HOMA_SOCKTAB_BUCKETS);
	mock_sock_init(&hsk3, &self->homa, first_port+2*HOMA_SOCKTAB_BUCKETS);
	mock_sock_init(&hsk4, &self->homa, first_port+5);
	hsk = homa_socktab_start_scan(&self->homa.port_map, &scan);
	EXPECT_EQ(first_port+2*HOMA_SOCKTAB_BUCKETS, hsk->port);
	hsk = homa_socktab_next(&scan);
	EXPECT_EQ(first_port+HOMA_SOCKTAB_BUCKETS, hsk->port);
	hsk = homa_socktab_next(&scan);
	EXPECT_EQ(first_port, hsk->port);
	hsk = homa_socktab_next(&scan);
	EXPECT_EQ(first_port+5, hsk->port);
	hsk = homa_socktab_next(&scan);
	EXPECT_EQ(NULL, hsk);
	homa_sock_destroy(&hsk1);
	homa_sock_destroy(&hsk2);
	homa_sock_destroy(&hsk3);
	homa_sock_destroy(&hsk4);
}
TEST_F(homa_sock, homa_socktab_next__deleted_socket)
{
	struct homa_sock hsk1, hsk2, hsk3, *hsk;
	struct homa_socktab_scan scan;
	int first_port = 34000;
	homa_destroy(&self->homa);
	homa_init(&self->homa);
	mock_sock_init(&hsk1, &self->homa, first_port);
	mock_sock_init(&hsk2, &self->homa, first_port+HOMA_SOCKTAB_BUCKETS);
	mock_sock_init(&hsk3, &self->homa, first_port+2*HOMA_SOCKTAB_BUCKETS);
	hsk = homa_socktab_start_scan(&self->homa.port_map, &scan);
	EXPECT_EQ(first_port+2*HOMA_SOCKTAB_BUCKETS, hsk->port);
	homa_sock_destroy(&hsk2);
	hsk = homa_socktab_next(&scan);
	EXPECT_EQ(first_port+HOMA_SOCKTAB_BUCKETS, hsk->port);
	EXPECT_EQ(1, hsk->shutdown);
	hsk = homa_socktab_next(&scan);
	EXPECT_EQ(first_port, hsk->port);
	hsk = homa_socktab_next(&scan);
	EXPECT_EQ(NULL, hsk);
	homa_sock_destroy(&hsk1);
	homa_sock_destroy(&hsk3);
}

TEST_F(homa_sock, homa_sock_init__skip_port_in_use)
{
	struct homa_sock hsk2, hsk3;
	self->homa.next_client_port = 0xffff;
	mock_sock_init(&hsk2, &self->homa, 0);
	mock_sock_init(&hsk3, &self->homa, 0);
	EXPECT_EQ(65535, hsk2.port);
	EXPECT_EQ(32769, hsk3.port);
	homa_sock_destroy(&hsk2);
	homa_sock_destroy(&hsk3);
}
TEST_F(homa_sock, homa_sock_init__ip_header_length)
{
	struct homa_sock hsk_v4, hsk_v6;
	mock_ipv6 = false;
	mock_sock_init(&hsk_v4, &self->homa, 0);
	mock_ipv6 = true;
	mock_sock_init(&hsk_v6, &self->homa, 0);
	EXPECT_EQ(HOMA_IPV4_HEADER_LENGTH, hsk_v4.ip_header_length);
	EXPECT_EQ(HOMA_IPV6_HEADER_LENGTH, hsk_v6.ip_header_length);
	homa_sock_destroy(&hsk_v4);
	homa_sock_destroy(&hsk_v6);
}
TEST_F(homa_sock, homa_sock_init__hijack_tcp)
{
	struct homa_sock hijack, no_hijack;
        self->homa.hijack_tcp = 0;
	mock_sock_init(&no_hijack, &self->homa, 0);
        self->homa.hijack_tcp = 1;
        mock_sock_init(&hijack, &self->homa, 0);
        EXPECT_EQ(0, no_hijack.sock.sk_protocol);
        EXPECT_EQ(IPPROTO_TCP, hijack.sock.sk_protocol);
        homa_sock_destroy(&hijack);
	homa_sock_destroy(&no_hijack);
}

TEST_F(homa_sock, homa_sock_shutdown__basics)
{
	int client2, client3;
	struct homa_sock hsk2, hsk3;
	mock_sock_init(&hsk2, &self->homa, 0);
	EXPECT_EQ(0, homa_sock_bind(&self->homa.port_map, &hsk2, 100));
	client2 = hsk2.port;
	mock_sock_init(&hsk3, &self->homa, 0);
	client3 = hsk3.port;

	EXPECT_EQ(&hsk2, homa_sock_find(&self->homa.port_map, client2));
	EXPECT_EQ(&hsk2, homa_sock_find(&self->homa.port_map, 100));
	EXPECT_EQ(&hsk3, homa_sock_find(&self->homa.port_map, client3));

	homa_sock_shutdown(&hsk2);

	EXPECT_EQ(NULL, homa_sock_find(&self->homa.port_map, client2));
	EXPECT_EQ(NULL, homa_sock_find(&self->homa.port_map, 100));
	EXPECT_EQ(&hsk3, homa_sock_find(&self->homa.port_map, client3));

	homa_sock_shutdown(&hsk3);

	EXPECT_EQ(NULL, homa_sock_find(&self->homa.port_map, client2));
	EXPECT_EQ(NULL, homa_sock_find(&self->homa.port_map, 100));
	EXPECT_EQ(NULL, homa_sock_find(&self->homa.port_map, client3));
}
TEST_F(homa_sock, homa_sock_shutdown__already_shutdown)
{
	unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, self->client_ip,
			self->server_ip, self->server_port, self->client_id,
			20000, 1600);
	unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			self->server_ip, self->server_port, self->client_id+2,
			5000, 5000);
	self->hsk.shutdown = 1;
	homa_sock_shutdown(&self->hsk);
	EXPECT_TRUE(self->hsk.shutdown);
	EXPECT_EQ(2 ,unit_list_length(&self->hsk.active_rpcs));
	self->hsk.shutdown = 0;
}
TEST_F(homa_sock, homa_sock_shutdown__delete_rpcs)
{
	unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, self->client_ip,
			self->server_ip, self->server_port, self->client_id,
			20000, 1600);
	unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			self->server_ip, self->server_port, self->client_id+2,
			5000, 5000);
	homa_sock_shutdown(&self->hsk);
	EXPECT_TRUE(self->hsk.shutdown);
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
}
TEST_F(homa_sock, homa_sock_shutdown__wakeup_interests)
{
	struct homa_interest interest1, interest2, interest3;
	struct task_struct task1, task2, task3;
	interest1.thread = &task1;
	task1.pid = 100;
	interest2.thread = &task2;
	task2.pid = 200;
	interest3.thread = &task3;
	task3.pid = 300;
	EXPECT_FALSE(self->hsk.shutdown);
	list_add_tail(&interest1.request_links, &self->hsk.request_interests);
	list_add_tail(&interest2.request_links, &self->hsk.request_interests);
	list_add_tail(&interest3.response_links, &self->hsk.response_interests);
	homa_sock_shutdown(&self->hsk);
	EXPECT_TRUE(self->hsk.shutdown);
	EXPECT_STREQ("wake_up_process pid -1; wake_up_process pid 100; "
			"wake_up_process pid 200; wake_up_process pid 300",
			unit_log_get());
}

TEST_F(homa_sock, homa_sock_bind)
{
	struct homa_sock hsk2;
	mock_sock_init(&hsk2, &self->homa, 0);
	EXPECT_EQ(0, homa_sock_bind(&self->homa.port_map, &hsk2, 100));

	EXPECT_EQ(0, -homa_sock_bind(&self->homa.port_map, &self->hsk, 0));
	EXPECT_EQ(HOMA_MIN_DEFAULT_PORT, self->hsk.port);
	EXPECT_EQ(EINVAL, -homa_sock_bind(&self->homa.port_map, &self->hsk,
			HOMA_MIN_DEFAULT_PORT + 100));

	EXPECT_EQ(EADDRINUSE, -homa_sock_bind(&self->homa.port_map, &self->hsk,
			100));
	EXPECT_EQ(0, -homa_sock_bind(&self->homa.port_map, &hsk2,
			100));

	EXPECT_EQ(0, -homa_sock_bind(&self->homa.port_map, &self->hsk,
			110));

	EXPECT_EQ(&self->hsk, homa_sock_find(&self->homa.port_map, 110));
	EXPECT_EQ(0, -homa_sock_bind(&self->homa.port_map, &self->hsk,
			120));
	EXPECT_EQ(NULL, homa_sock_find(&self->homa.port_map, 110));
	EXPECT_EQ(&self->hsk, homa_sock_find(&self->homa.port_map, 120));
	homa_sock_destroy(&hsk2);
}
TEST_F(homa_sock, homa_sock_bind__socket_shutdown)
{
	homa_sock_shutdown(&self->hsk);
	EXPECT_EQ(ESHUTDOWN, -homa_sock_bind(&self->homa.port_map, &self->hsk,
			100));
}

TEST_F(homa_sock, homa_sock_find__basics)
{
	struct homa_sock hsk2;
	mock_sock_init(&hsk2, &self->homa, 0);
	EXPECT_EQ(0, homa_sock_bind(&self->homa.port_map, &hsk2, 100));
	EXPECT_EQ(&self->hsk, homa_sock_find(&self->homa.port_map,
			self->hsk.port));
	EXPECT_EQ(&hsk2, homa_sock_find(&self->homa.port_map,
			hsk2.port));
	EXPECT_EQ(NULL, homa_sock_find(&self->homa.port_map,
			hsk2.port + 1));
	homa_sock_destroy(&hsk2);
}

TEST_F(homa_sock, homa_sock_find__long_hash_chain)
{
	struct homa_sock hsk2, hsk3, hsk4;
	EXPECT_EQ(0, homa_sock_bind(&self->homa.port_map, &self->hsk, 13));
	mock_sock_init(&hsk2, &self->homa, 0);
	EXPECT_EQ(0, homa_sock_bind(&self->homa.port_map, &hsk2,
			2*HOMA_SOCKTAB_BUCKETS + 13));
	mock_sock_init(&hsk3, &self->homa, 0);
	EXPECT_EQ(0, homa_sock_bind(&self->homa.port_map, &hsk3,
			3*HOMA_SOCKTAB_BUCKETS + 13));
	mock_sock_init(&hsk4, &self->homa, 0);
	EXPECT_EQ(0, homa_sock_bind(&self->homa.port_map, &hsk4,
			5*HOMA_SOCKTAB_BUCKETS + 13));

	EXPECT_EQ(&self->hsk, homa_sock_find(&self->homa.port_map,
			13));
	EXPECT_EQ(&hsk2, homa_sock_find(&self->homa.port_map,
			2*HOMA_SOCKTAB_BUCKETS + 13));
	EXPECT_EQ(&hsk3, homa_sock_find(&self->homa.port_map,
			3*HOMA_SOCKTAB_BUCKETS + 13));
	EXPECT_EQ(&hsk4, homa_sock_find(&self->homa.port_map,
			5*HOMA_SOCKTAB_BUCKETS + 13));

	homa_sock_destroy(&hsk2);
	homa_sock_destroy(&hsk3);
	homa_sock_destroy(&hsk4);
}

TEST_F(homa_sock, homa_sock_lock_slow)
{
	mock_cycles = ~0;

	homa_sock_lock(&self->hsk, "unit test");
	EXPECT_EQ(0, homa_metrics_per_cpu()->socket_lock_misses);
	EXPECT_EQ(0, homa_metrics_per_cpu()->socket_lock_miss_cycles);
	homa_sock_unlock(&self->hsk);

	mock_trylock_errors = 1;
	homa_sock_lock(&self->hsk, "unit test");
	EXPECT_EQ(1, homa_metrics_per_cpu()->socket_lock_misses);
	EXPECT_NE(0, homa_metrics_per_cpu()->socket_lock_miss_cycles);
	homa_sock_unlock(&self->hsk);
}