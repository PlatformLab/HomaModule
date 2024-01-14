/* Copyright (c) 2019-2023 Homa Developers
 * SPDX-License-Identifier: BSD-1-Clause
 */

#include "homa_impl.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

char *rpc_ids(struct homa_rpc **rpcs, int count)
{
	static char buffer[1000];
	size_t length = 0;
	int i;

	for (i = 0; i < count; i++) {
		if (length != 0)
			length += snprintf(buffer + length,
					sizeof(buffer) - length, " ");
		length += snprintf(buffer + length, sizeof(buffer) - length,
				"%lld", rpcs[i]->id);
	}
	return buffer;
}

FIXTURE(homa_grant) {
	struct in6_addr client_ip[5];
	int client_port;
	struct in6_addr server_ip[5];
	int server_port;
	__u64 client_id;
	__u64 server_id;
	sockaddr_in_union server_addr;
	struct homa homa;
	struct homa_sock hsk;
	struct data_header data;
	int incoming_delta;
};
FIXTURE_SETUP(homa_grant)
{
	self->client_ip[0] = unit_get_in_addr("196.168.0.1");
	self->client_ip[1] = unit_get_in_addr("197.168.0.1");
	self->client_ip[2] = unit_get_in_addr("198.168.0.1");
	self->client_ip[3] = unit_get_in_addr("199.168.0.1");
	self->client_ip[4] = unit_get_in_addr("200.168.0.1");
	self->client_port = 40000;
	self->server_ip[0] = unit_get_in_addr("1.2.3.4");
	self->server_ip[1] = unit_get_in_addr("2.2.3.4");
	self->server_ip[2] = unit_get_in_addr("3.2.3.4");
	self->server_ip[3] = unit_get_in_addr("4.2.3.4");
	self->server_ip[4] = unit_get_in_addr("5.2.3.4");
	self->server_port = 99;
	self->client_id = 1234;
	self->server_id = 1235;
	homa_init(&self->homa);
	self->homa.num_priorities = 1;
	self->homa.poll_cycles = 0;
	self->homa.flags |= HOMA_FLAG_DONT_THROTTLE;
	self->homa.pacer_fifo_fraction = 0;
	self->homa.grant_fifo_fraction = 0;
	mock_sock_init(&self->hsk, &self->homa, 0);
	self->server_addr.in6.sin6_family = self->hsk.inet.sk.sk_family;
	self->server_addr.in6.sin6_addr = self->server_ip[0];
	self->server_addr.in6.sin6_port =  htons(self->server_port);
	self->data = (struct data_header){.common = {
			.sport = htons(self->client_port),
	                .dport = htons(self->server_port),
			.type = DATA,
			.sender_id = cpu_to_be64(self->client_id)},
			.message_length = htonl(10000),
			.incoming = htonl(10000), .cutoff_version = 0,
		        .retransmit = 0,
			.seg = {.offset = 0, .segment_length = htonl(1400),
				.ack = {0, 0, 0}}};
	unit_log_clear();
	self->incoming_delta = 0;
}
FIXTURE_TEARDOWN(homa_grant)
{
	homa_destroy(&self->homa);
	unit_teardown();
}

static struct homa_rpc *test_rpc(FIXTURE_DATA(homa_grant) *self,
		__u64 id, struct in6_addr *server_ip, int size)
{
	struct homa_rpc *rpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING,
			self->client_ip, server_ip, self->server_port,
			id, 1000, size);
	homa_message_in_init(rpc, size, 0);
	homa_grant_add_rpc(rpc);
	return rpc;
}

TEST_F(homa_grant, homa_grant_prio)
{
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->server_port,
			100, 1000, 20000);
	struct homa_rpc *crpc2 = unit_client_rpc(&self->hsk,UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->server_port,
			102, 1000, 30000);
	struct homa_rpc *crpc3 = unit_client_rpc(&self->hsk,UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->server_port,
			104, 1000, 30000);
	struct homa_rpc *crpc4 = unit_client_rpc(&self->hsk,UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->server_port,
			106, 1000, 30000);

	homa_message_in_init(crpc1, 20000, 0);
	crpc1->msgin.birth = 3000;
	homa_message_in_init(crpc2, 30000, 0);
	crpc2->msgin.birth = 2000;
	homa_message_in_init(crpc3, 30000, 0);
	crpc3->msgin.birth = 1999;
	homa_message_in_init(crpc4, 30000, 0);
	crpc4->msgin.birth = 2000;

	EXPECT_EQ(1, homa_grant_prio(crpc1, crpc2));
	EXPECT_EQ(0, homa_grant_prio(crpc2, crpc1));
	EXPECT_EQ(0, homa_grant_prio(crpc2, crpc3));
	EXPECT_EQ(1, homa_grant_prio(crpc3, crpc2));
	EXPECT_EQ(0, homa_grant_prio(crpc2, crpc4));
	EXPECT_EQ(0, homa_grant_prio(crpc4, crpc2));
}

TEST_F(homa_grant, homa_grant_add_rpc__insert_in_peer_list)
{
	test_rpc(self, 100, self->server_ip, 100000);
	test_rpc(self, 200, self->server_ip, 50000);
	test_rpc(self, 300, self->server_ip, 120000);
	test_rpc(self, 400, self->server_ip, 70000);

	unit_log_clear();
	unit_log_grantables2(&self->homa);
	EXPECT_STREQ("response from 1.2.3.4, id 200, remaining 50000; "
			"response from 1.2.3.4, id 400, remaining 70000; "
			"response from 1.2.3.4, id 100, remaining 100000; "
			"response from 1.2.3.4, id 300, remaining 120000",
			unit_log_get());
}
TEST_F(homa_grant, homa_grant_add_rpc__adjust_order_in_peer_list)
{
	test_rpc(self, 200, self->server_ip, 20000);
	test_rpc(self, 300, self->server_ip, 30000);
	struct homa_rpc *rpc3 = test_rpc(self, 400, self->server_ip, 40000);
	test_rpc(self, 500, self->server_ip, 50000);

	unit_log_clear();
	unit_log_grantables2(&self->homa);
	EXPECT_STREQ("response from 1.2.3.4, id 200, remaining 20000; "
			"response from 1.2.3.4, id 300, remaining 30000; "
			"response from 1.2.3.4, id 400, remaining 40000; "
			"response from 1.2.3.4, id 500, remaining 50000",
			unit_log_get());

	rpc3->msgin.bytes_remaining = 30000;
	homa_grant_add_rpc(rpc3);
	unit_log_clear();
	unit_log_grantables2(&self->homa);
	EXPECT_STREQ("response from 1.2.3.4, id 200, remaining 20000; "
			"response from 1.2.3.4, id 300, remaining 30000; "
			"response from 1.2.3.4, id 400, remaining 30000; "
			"response from 1.2.3.4, id 500, remaining 50000",
			unit_log_get());

	rpc3->msgin.bytes_remaining = 19999;
	homa_grant_add_rpc(rpc3);
	unit_log_clear();
	unit_log_grantables2(&self->homa);
	EXPECT_STREQ("response from 1.2.3.4, id 400, remaining 19999; "
			"response from 1.2.3.4, id 200, remaining 20000; "
			"response from 1.2.3.4, id 300, remaining 30000; "
			"response from 1.2.3.4, id 500, remaining 50000",
			unit_log_get());
}
TEST_F(homa_grant, homa_grant_add_rpc__insert_peer_in_homa_list)
{
	test_rpc(self, 200, self->server_ip, 100000);
	test_rpc(self, 300, self->server_ip+1, 50000);
	test_rpc(self, 400, self->server_ip+2, 120000);
	test_rpc(self, 500, self->server_ip+3, 70000);

	unit_log_clear();
	unit_log_grantables2(&self->homa);
	EXPECT_STREQ("response from 2.2.3.4, id 300, remaining 50000; "
			"response from 4.2.3.4, id 500, remaining 70000; "
			"response from 1.2.3.4, id 200, remaining 100000; "
			"response from 3.2.3.4, id 400, remaining 120000",
			unit_log_get());
}
TEST_F(homa_grant, homa_grant_add_rpc__move_peer_in_homa_list)
{
	test_rpc(self, 200, self->server_ip, 20000);
	test_rpc(self, 300, self->server_ip+1, 30000);
	struct homa_rpc *rpc3 = test_rpc(self, 400, self->server_ip+2, 40000);
	struct homa_rpc *rpc4 = test_rpc(self, 500, self->server_ip+3, 50000);

	unit_log_clear();
	unit_log_grantables2(&self->homa);
	EXPECT_STREQ("response from 1.2.3.4, id 200, remaining 20000; "
			"response from 2.2.3.4, id 300, remaining 30000; "
			"response from 3.2.3.4, id 400, remaining 40000; "
			"response from 4.2.3.4, id 500, remaining 50000",
			unit_log_get());

	rpc3->msgin.bytes_remaining = 30000;
	homa_grant_add_rpc(rpc3);
	unit_log_clear();
	unit_log_grantables2(&self->homa);
	EXPECT_STREQ("response from 1.2.3.4, id 200, remaining 20000; "
			"response from 2.2.3.4, id 300, remaining 30000; "
			"response from 3.2.3.4, id 400, remaining 30000; "
			"response from 4.2.3.4, id 500, remaining 50000",
			unit_log_get());

	rpc4->msgin.bytes_remaining = 19999;
	homa_grant_add_rpc(rpc4);
	unit_log_clear();
	unit_log_grantables2(&self->homa);
	EXPECT_STREQ("response from 4.2.3.4, id 500, remaining 19999; "
			"response from 1.2.3.4, id 200, remaining 20000; "
			"response from 2.2.3.4, id 300, remaining 30000; "
			"response from 3.2.3.4, id 400, remaining 30000",
			unit_log_get());
}

TEST_F(homa_grant, homa_grant_remove_rpc__not_first_in_peer_list)
{
	test_rpc(self, 200, self->server_ip, 20000);
	struct homa_rpc *rpc2 = test_rpc(self, 300, self->server_ip, 30000);
	test_rpc(self, 400, self->server_ip+1, 25000);

	unit_log_clear();
	unit_log_grantables2(&self->homa);
	EXPECT_STREQ("response from 1.2.3.4, id 200, remaining 20000; "
			"response from 1.2.3.4, id 300, remaining 30000; "
			"response from 2.2.3.4, id 400, remaining 25000",
			unit_log_get());

	homa_grant_remove_rpc(rpc2);
	unit_log_clear();
	unit_log_grantables2(&self->homa);
	EXPECT_STREQ("response from 1.2.3.4, id 200, remaining 20000; "
			"response from 2.2.3.4, id 400, remaining 25000",
			unit_log_get());
}
TEST_F(homa_grant, homa_grant_remove_rpc__only_entry_in_peer_list)
{
	struct homa_rpc *rpc1 = test_rpc(self, 200, self->server_ip, 30000);
	test_rpc(self, 300, self->server_ip+1, 40000);
	test_rpc(self, 400, self->server_ip+2, 20000);

	unit_log_clear();
	unit_log_grantables2(&self->homa);
	EXPECT_STREQ("response from 3.2.3.4, id 400, remaining 20000; "
			"response from 1.2.3.4, id 200, remaining 30000; "
			"response from 2.2.3.4, id 300, remaining 40000",
			unit_log_get());

	homa_grant_remove_rpc(rpc1);
	unit_log_clear();
	unit_log_grantables2(&self->homa);
	EXPECT_STREQ("response from 3.2.3.4, id 400, remaining 20000; "
			"response from 2.2.3.4, id 300, remaining 40000",
			unit_log_get());
}
TEST_F(homa_grant, homa_grant_remove_rpc__reposition_peer_in_homa_list)
{
	struct homa_rpc *rpc1 = test_rpc(self, 200, self->server_ip, 20000);
	test_rpc(self, 300, self->server_ip, 50000);
	test_rpc(self, 400, self->server_ip+1, 30000);
	test_rpc(self, 500, self->server_ip+2, 40000);

	unit_log_clear();
	unit_log_grantables2(&self->homa);
	EXPECT_STREQ("response from 1.2.3.4, id 200, remaining 20000; "
			"response from 1.2.3.4, id 300, remaining 50000; "
			"response from 2.2.3.4, id 400, remaining 30000; "
			"response from 3.2.3.4, id 500, remaining 40000",
			unit_log_get());

	homa_grant_remove_rpc(rpc1);
	unit_log_clear();
	unit_log_grantables2(&self->homa);
	EXPECT_STREQ("response from 2.2.3.4, id 400, remaining 30000; "
			"response from 3.2.3.4, id 500, remaining 40000; "
			"response from 1.2.3.4, id 300, remaining 50000",
			unit_log_get());
}

TEST_F(homa_grant, homa_grant_pick_rpcs__basics)
{
	struct homa_rpc *rpcs[4];
	int count;

	test_rpc(self, 200, self->server_ip, 20000);
	test_rpc(self, 300, self->server_ip, 50000);
	test_rpc(self, 400, self->server_ip+1, 30000);
	test_rpc(self, 500, self->server_ip+2, 40000);

	self->homa.max_rpcs_per_peer = 2;
	count = homa_grant_pick_rpcs(&self->homa, rpcs, 4);
	EXPECT_EQ(4, count);
	EXPECT_STREQ("200 400 500 300", rpc_ids(rpcs, count));
}
TEST_F(homa_grant, homa_grant_pick_rpcs__new_rpc_goes_in_middle_of_list)
{
	struct homa_rpc *rpcs[4];
	int count;

	test_rpc(self, 200, self->server_ip, 20000);
	test_rpc(self, 300, self->server_ip, 30000);
	test_rpc(self, 400, self->server_ip, 40000);
	test_rpc(self, 500, self->server_ip+1, 25000);

	self->homa.max_rpcs_per_peer = 3;
	count = homa_grant_pick_rpcs(&self->homa, rpcs, 4);
	EXPECT_EQ(4, count);
	EXPECT_STREQ("200 500 300 400", rpc_ids(rpcs, count));
}
TEST_F(homa_grant, homa_grant_pick_rpcs__non_first_rpc_of_peer_doesnt_fit)
{
	struct homa_rpc *rpcs[4];
	int count;

	test_rpc(self, 200, self->server_ip, 20000);
	test_rpc(self, 300, self->server_ip, 30000);
	test_rpc(self, 400, self->server_ip, 40000);
	test_rpc(self, 400, self->server_ip, 50000);
	test_rpc(self, 500, self->server_ip+1, 25000);

	self->homa.max_rpcs_per_peer = 3;
	count = homa_grant_pick_rpcs(&self->homa, rpcs, 3);
	EXPECT_EQ(4, count);
	EXPECT_STREQ("200 500 300 400", rpc_ids(rpcs, count));
}
TEST_F(homa_grant, homa_grant_pick_rpcs__max_rpcs_per_peer)
{
	struct homa_rpc *rpcs[4];
	int count;

	test_rpc(self, 200, self->server_ip, 20000);
	test_rpc(self, 300, self->server_ip, 30000);
	test_rpc(self, 400, self->server_ip, 40000);
	test_rpc(self, 500, self->server_ip, 50000);
	test_rpc(self, 600, self->server_ip+1, 60000);

	self->homa.max_rpcs_per_peer = 2;
	count = homa_grant_pick_rpcs(&self->homa, rpcs, 4);
	EXPECT_EQ(3, count);
	EXPECT_STREQ("200 300 600", rpc_ids(rpcs, count));
}
TEST_F(homa_grant, homa_grant_pick_rpcs__first_rpc_of_peer_doesnt_fit)
{
	struct homa_rpc *rpcs[4];
	int count;

	test_rpc(self, 200, self->server_ip, 20000);
	test_rpc(self, 300, self->server_ip, 30000);
	test_rpc(self, 400, self->server_ip, 40000);
	test_rpc(self, 400, self->server_ip+1, 50000);
	test_rpc(self, 500, self->server_ip+2, 60000);

	self->homa.max_rpcs_per_peer = 3;
	count = homa_grant_pick_rpcs(&self->homa, rpcs, 3);
	EXPECT_EQ(3, count);
	EXPECT_STREQ("200 300 400", rpc_ids(rpcs, count));
}

TEST_F(homa_grant, homa_grant_update_incoming)
{
	struct homa_rpc *rpc;

	rpc = test_rpc(self, 200, self->server_ip, 20000);

	/* Case 1: total_incoming increases. */
	atomic_set(&self->homa.total_incoming, 1000);
	rpc->msgin.bytes_remaining = 19000;
	rpc->msgin.granted = 3000;
	rpc->msgin.rec_incoming = 500;
	homa_grant_update_incoming(rpc);
	EXPECT_EQ(2500, atomic_read(&self->homa.total_incoming));
	EXPECT_EQ(2000, rpc->msgin.rec_incoming);

	/* Case 2: total_incoming decreases. */
	atomic_set(&self->homa.total_incoming, 1000);
	rpc->msgin.bytes_remaining = 17000;
	rpc->msgin.granted = 3000;
	rpc->msgin.rec_incoming = 500;
	homa_grant_update_incoming(rpc);
	EXPECT_EQ(500, atomic_read(&self->homa.total_incoming));
	EXPECT_EQ(0, rpc->msgin.rec_incoming);

	/* Case 3: new_incoming negative. */
	atomic_set(&self->homa.total_incoming, 1000);
	rpc->msgin.bytes_remaining = 16000;
	rpc->msgin.granted = 3000;
	rpc->msgin.rec_incoming = 500;
	homa_grant_update_incoming(rpc);
	EXPECT_EQ(500, atomic_read(&self->homa.total_incoming));
	EXPECT_EQ(0, rpc->msgin.rec_incoming);

	/* Case 4: no change to rec_incoming. */
	atomic_set(&self->homa.total_incoming, 1000);
	rpc->msgin.bytes_remaining = 16000;
	rpc->msgin.granted = 4500;
	rpc->msgin.rec_incoming = 500;
	homa_grant_update_incoming(rpc);
	EXPECT_EQ(1000, atomic_read(&self->homa.total_incoming));
	EXPECT_EQ(500, rpc->msgin.rec_incoming);
}