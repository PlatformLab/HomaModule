// SPDX-License-Identifier: BSD-2-Clause

#include "homa_impl.h"
#include "homa_grant.h"
#include "homa_rpc.h"
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

static struct homa *hook_homa;
static void grantable_spinlock_hook(char *id)
{
	if (strcmp(id, "spin_lock") != 0)
		return;
	if (hook_homa != NULL)
		atomic_inc(&hook_homa->grant_recalc_count);
	mock_ns = 1000;
}

FIXTURE(homa_grant) {
	struct in6_addr client_ip[5];
	int client_port;
	struct in6_addr server_ip[5];
	int server_port;
	u64 client_id;
	u64 server_id;
	union sockaddr_in_union server_addr;
	struct homa homa;
	struct homa_sock hsk;
	struct homa_data_hdr data;
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
	self->homa.poll_usecs = 0;
	self->homa.flags |= HOMA_FLAG_DONT_THROTTLE;
	self->homa.pacer_fifo_fraction = 0;
	self->homa.grant_fifo_fraction = 0;
	self->homa.window_param = 10000;
	self->homa.grant_window = 10000;
	self->homa.max_incoming = 50000;
	self->homa.max_rpcs_per_peer = 10;
	mock_sock_init(&self->hsk, &self->homa, 0);
	self->server_addr.in6.sin6_family = self->hsk.inet.sk.sk_family;
	self->server_addr.in6.sin6_addr = self->server_ip[0];
	self->server_addr.in6.sin6_port =  htons(self->server_port);
	memset(&self->data, 0, sizeof(self->data));
	self->data.common = (struct homa_common_hdr){
		.sport = htons(self->client_port),
		.dport = htons(self->server_port),
		.type = DATA,
		.sender_id = cpu_to_be64(self->client_id)
	};
	self->data.message_length = htonl(10000);
	self->data.incoming = htonl(10000);
	unit_log_clear();
	self->incoming_delta = 0;
}
FIXTURE_TEARDOWN(homa_grant)
{
	homa_destroy(&self->homa);
	unit_teardown();
}

static struct homa_rpc *test_rpc(FIXTURE_DATA(homa_grant) *self,
		u64 id, struct in6_addr *server_ip, int size)
{
	struct homa_rpc *rpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING,
			self->client_ip, server_ip, self->server_port,
			id, 1000, size);

	homa_message_in_init(rpc, size, 0);
	homa_grant_add_rpc(rpc);
	return rpc;
}

TEST_F(homa_grant, homa_grant_outranks)
{
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk, UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->server_port,
			100, 1000, 20000);
	struct homa_rpc *crpc2 = unit_client_rpc(&self->hsk, UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->server_port,
			102, 1000, 30000);
	struct homa_rpc *crpc3 = unit_client_rpc(&self->hsk, UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->server_port,
			104, 1000, 30000);
	struct homa_rpc *crpc4 = unit_client_rpc(&self->hsk, UNIT_OUTGOING,
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

	EXPECT_EQ(1, homa_grant_outranks(crpc1, crpc2));
	EXPECT_EQ(0, homa_grant_outranks(crpc2, crpc1));
	EXPECT_EQ(0, homa_grant_outranks(crpc2, crpc3));
	EXPECT_EQ(1, homa_grant_outranks(crpc3, crpc2));
	EXPECT_EQ(0, homa_grant_outranks(crpc2, crpc4));
	EXPECT_EQ(0, homa_grant_outranks(crpc4, crpc2));
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
	EXPECT_EQ(0, homa_grant_update_incoming(rpc, &self->homa));
	EXPECT_EQ(2500, atomic_read(&self->homa.total_incoming));
	EXPECT_EQ(2000, rpc->msgin.rec_incoming);

	/* Case 2: incoming negative. */
	atomic_set(&self->homa.total_incoming, 1000);
	rpc->msgin.bytes_remaining = 16000;
	rpc->msgin.granted = 3000;
	rpc->msgin.rec_incoming = 500;
	EXPECT_EQ(0, homa_grant_update_incoming(rpc, &self->homa));
	EXPECT_EQ(500, atomic_read(&self->homa.total_incoming));
	EXPECT_EQ(0, rpc->msgin.rec_incoming);

	/* Case 3: total_incoming decreases below max_incoming. */
	atomic_set(&self->homa.total_incoming, 5000);
	self->homa.max_incoming = 5000;
	rpc->msgin.bytes_remaining = 17000;
	rpc->msgin.granted = 4000;
	rpc->msgin.rec_incoming = 2000;
	EXPECT_EQ(1, homa_grant_update_incoming(rpc, &self->homa));
	EXPECT_EQ(4000, atomic_read(&self->homa.total_incoming));
	EXPECT_EQ(1000, rpc->msgin.rec_incoming);

	/* Case 4: no change to rec_incoming. */
	atomic_set(&self->homa.total_incoming, 1000);
	self->homa.max_incoming = 1000;
	rpc->msgin.bytes_remaining = 16000;
	rpc->msgin.granted = 4500;
	rpc->msgin.rec_incoming = 500;
	EXPECT_EQ(0, homa_grant_update_incoming(rpc, &self->homa));
	EXPECT_EQ(1000, atomic_read(&self->homa.total_incoming));
	EXPECT_EQ(500, rpc->msgin.rec_incoming);
}

TEST_F(homa_grant, homa_grant_add_rpc__update_metrics)
{
	self->homa.last_grantable_change = 100;
	self->homa.num_grantable_rpcs = 3;
	mock_ns = 200;
	test_rpc(self, 100, self->server_ip, 100000);
	EXPECT_EQ(4, self->homa.num_grantable_rpcs);
	EXPECT_EQ(300, homa_metrics_per_cpu()->grantable_rpcs_integral);
	EXPECT_EQ(200, self->homa.last_grantable_change);
}
TEST_F(homa_grant, homa_grant_add_rpc__insert_in_peer_list)
{
	test_rpc(self, 100, self->server_ip, 100000);
	test_rpc(self, 200, self->server_ip, 50000);
	test_rpc(self, 300, self->server_ip, 120000);
	test_rpc(self, 400, self->server_ip, 70000);

	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("response from 1.2.3.4, id 200, remaining 50000; "
			"response from 1.2.3.4, id 400, remaining 70000; "
			"response from 1.2.3.4, id 100, remaining 100000; "
			"response from 1.2.3.4, id 300, remaining 120000",
			unit_log_get());
	EXPECT_EQ(4, self->homa.num_grantable_rpcs);
}
TEST_F(homa_grant, homa_grant_add_rpc__adjust_order_in_peer_list)
{
	struct homa_rpc *rpc3;

	test_rpc(self, 200, self->server_ip, 20000);
	test_rpc(self, 300, self->server_ip, 30000);
	rpc3 = test_rpc(self, 400, self->server_ip, 40000);
	test_rpc(self, 500, self->server_ip, 50000);

	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("response from 1.2.3.4, id 200, remaining 20000; "
			"response from 1.2.3.4, id 300, remaining 30000; "
			"response from 1.2.3.4, id 400, remaining 40000; "
			"response from 1.2.3.4, id 500, remaining 50000",
			unit_log_get());

	rpc3->msgin.bytes_remaining = 30000;
	homa_grant_add_rpc(rpc3);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("response from 1.2.3.4, id 200, remaining 20000; "
			"response from 1.2.3.4, id 300, remaining 30000; "
			"response from 1.2.3.4, id 400, remaining 30000; "
			"response from 1.2.3.4, id 500, remaining 50000",
			unit_log_get());

	rpc3->msgin.bytes_remaining = 19999;
	homa_grant_add_rpc(rpc3);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("response from 1.2.3.4, id 400, remaining 19999; "
			"response from 1.2.3.4, id 200, remaining 20000; "
			"response from 1.2.3.4, id 300, remaining 30000; "
			"response from 1.2.3.4, id 500, remaining 50000",
			unit_log_get());
	EXPECT_EQ(4, self->homa.num_grantable_rpcs);
}
TEST_F(homa_grant, homa_grant_add_rpc__insert_peer_in_homa_list)
{
	test_rpc(self, 200, self->server_ip, 100000);
	test_rpc(self, 300, self->server_ip+1, 50000);
	test_rpc(self, 400, self->server_ip+2, 120000);
	test_rpc(self, 500, self->server_ip+3, 70000);

	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("response from 2.2.3.4, id 300, remaining 50000; "
			"response from 4.2.3.4, id 500, remaining 70000; "
			"response from 1.2.3.4, id 200, remaining 100000; "
			"response from 3.2.3.4, id 400, remaining 120000",
			unit_log_get());
	EXPECT_EQ(4, self->homa.num_grantable_rpcs);
}
TEST_F(homa_grant, homa_grant_add_rpc__move_peer_in_homa_list)
{
	struct homa_rpc *rpc3;
	struct homa_rpc *rpc4;

	test_rpc(self, 200, self->server_ip, 20000);
	test_rpc(self, 300, self->server_ip+1, 30000);
	rpc3 = test_rpc(self, 400, self->server_ip+2, 40000);
	rpc4 = test_rpc(self, 500, self->server_ip+3, 50000);

	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("response from 1.2.3.4, id 200, remaining 20000; "
			"response from 2.2.3.4, id 300, remaining 30000; "
			"response from 3.2.3.4, id 400, remaining 40000; "
			"response from 4.2.3.4, id 500, remaining 50000",
			unit_log_get());

	rpc3->msgin.bytes_remaining = 30000;
	homa_grant_add_rpc(rpc3);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("response from 1.2.3.4, id 200, remaining 20000; "
			"response from 2.2.3.4, id 300, remaining 30000; "
			"response from 3.2.3.4, id 400, remaining 30000; "
			"response from 4.2.3.4, id 500, remaining 50000",
			unit_log_get());

	rpc4->msgin.bytes_remaining = 19999;
	homa_grant_add_rpc(rpc4);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("response from 4.2.3.4, id 500, remaining 19999; "
			"response from 1.2.3.4, id 200, remaining 20000; "
			"response from 2.2.3.4, id 300, remaining 30000; "
			"response from 3.2.3.4, id 400, remaining 30000",
			unit_log_get());
	EXPECT_EQ(4, self->homa.num_grantable_rpcs);
}

TEST_F(homa_grant, homa_grant_remove_rpc__skip_if_not_linked)
{
	struct homa_rpc *rpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->server_port,
			100, 1000, 2000);

	unit_log_grantables(&self->homa);
	EXPECT_EQ(0, self->homa.num_grantable_rpcs);

	homa_grant_remove_rpc(rpc);
	EXPECT_EQ(0, self->homa.num_grantable_rpcs);
}
TEST_F(homa_grant, homa_grant_remove_rpc__clear_oldest_rpc)
{
	struct homa_rpc *rpc1 = test_rpc(self, 200, self->server_ip, 20000);
	struct homa_rpc *rpc2 = test_rpc(self, 300, self->server_ip, 10000);

	EXPECT_EQ(2, self->homa.num_grantable_rpcs);
	self->homa.oldest_rpc = rpc2;

	homa_grant_remove_rpc(rpc1);
	EXPECT_NE(NULL, self->homa.oldest_rpc);
	EXPECT_EQ(300, self->homa.oldest_rpc->id);

	homa_grant_remove_rpc(rpc2);
	EXPECT_EQ(NULL, self->homa.oldest_rpc);
}
TEST_F(homa_grant, homa_grant_remove_rpc__update_metrics)
{
	struct homa_rpc *rpc = test_rpc(self, 200, self->server_ip, 20000);

	EXPECT_EQ(1, self->homa.num_grantable_rpcs);
	self->homa.last_grantable_change = 100;
	self->homa.num_grantable_rpcs = 3;
	mock_ns = 200;

	homa_grant_remove_rpc(rpc);
	EXPECT_EQ(2, self->homa.num_grantable_rpcs);
	EXPECT_EQ(300, homa_metrics_per_cpu()->grantable_rpcs_integral);
	EXPECT_EQ(200, self->homa.last_grantable_change);
}
TEST_F(homa_grant, homa_grant_remove_rpc__not_first_in_peer_list)
{
	struct homa_rpc *rpc2;

	test_rpc(self, 200, self->server_ip, 20000);
	rpc2 = test_rpc(self, 300, self->server_ip, 30000);
	test_rpc(self, 400, self->server_ip+1, 25000);

	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("response from 1.2.3.4, id 200, remaining 20000; "
			"response from 1.2.3.4, id 300, remaining 30000; "
			"response from 2.2.3.4, id 400, remaining 25000",
			unit_log_get());

	homa_grant_remove_rpc(rpc2);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("response from 1.2.3.4, id 200, remaining 20000; "
			"response from 2.2.3.4, id 400, remaining 25000",
			unit_log_get());
	EXPECT_EQ(2, self->homa.num_grantable_rpcs);
}
TEST_F(homa_grant, homa_grant_remove_rpc__only_entry_in_peer_list)
{
	struct homa_rpc *rpc1 = test_rpc(self, 200, self->server_ip, 30000);

	test_rpc(self, 300, self->server_ip+1, 40000);
	test_rpc(self, 400, self->server_ip+2, 20000);

	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("response from 3.2.3.4, id 400, remaining 20000; "
			"response from 1.2.3.4, id 200, remaining 30000; "
			"response from 2.2.3.4, id 300, remaining 40000",
			unit_log_get());

	homa_grant_remove_rpc(rpc1);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("response from 3.2.3.4, id 400, remaining 20000; "
			"response from 2.2.3.4, id 300, remaining 40000",
			unit_log_get());
	EXPECT_EQ(2, self->homa.num_grantable_rpcs);
}
TEST_F(homa_grant, homa_grant_remove_rpc__reposition_peer_in_homa_list)
{
	struct homa_rpc *rpc1 = test_rpc(self, 200, self->server_ip, 20000);

	test_rpc(self, 300, self->server_ip, 50000);
	test_rpc(self, 400, self->server_ip+1, 30000);
	test_rpc(self, 500, self->server_ip+2, 40000);

	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("response from 1.2.3.4, id 200, remaining 20000; "
			"response from 1.2.3.4, id 300, remaining 50000; "
			"response from 2.2.3.4, id 400, remaining 30000; "
			"response from 3.2.3.4, id 500, remaining 40000",
			unit_log_get());

	homa_grant_remove_rpc(rpc1);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("response from 2.2.3.4, id 400, remaining 30000; "
			"response from 3.2.3.4, id 500, remaining 40000; "
			"response from 1.2.3.4, id 300, remaining 50000",
			unit_log_get());
	EXPECT_EQ(3, self->homa.num_grantable_rpcs);
}

TEST_F(homa_grant, homa_grant_send__basics)
{
	struct homa_rpc *rpc = test_rpc(self, 100, self->server_ip, 20000);
	int granted;

	rpc->msgin.priority = 3;
	unit_log_clear();
	granted = homa_grant_send(rpc, &self->homa);
	EXPECT_EQ(1, granted);
	EXPECT_EQ(10000, rpc->msgin.granted);
	EXPECT_STREQ("xmit GRANT 10000@3", unit_log_get());
}
TEST_F(homa_grant, homa_grant_send__incoming_negative)
{
	struct homa_rpc *rpc = test_rpc(self, 100, self->server_ip, 20000);
	int granted;

	rpc->msgin.bytes_remaining = 5000;
	atomic_set(&self->homa.total_incoming, self->homa.max_incoming);

	unit_log_clear();
	granted = homa_grant_send(rpc, &self->homa);
	EXPECT_EQ(0, granted);
	EXPECT_EQ(15000, rpc->msgin.granted);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_grant, homa_grant_send__end_of_message)
{
	struct homa_rpc *rpc = test_rpc(self, 100, self->server_ip, 20000);
	int granted;

	rpc->msgin.bytes_remaining = 5000;
	unit_log_clear();
	granted = homa_grant_send(rpc, &self->homa);
	EXPECT_EQ(1, granted);
	EXPECT_EQ(20000, rpc->msgin.granted);
	EXPECT_STREQ("xmit GRANT 20000@0", unit_log_get());
}
TEST_F(homa_grant, homa_grant_send__not_enough_available_bytes)
{
	struct homa_rpc *rpc = test_rpc(self, 100, self->server_ip, 20000);
	int granted;

	rpc->msgin.granted = 3000;
	rpc->msgin.rec_incoming = 4000;
	atomic_set(&self->homa.total_incoming, self->homa.max_incoming - 4000);

	unit_log_clear();
	granted = homa_grant_send(rpc, &self->homa);
	EXPECT_EQ(1, granted);
	EXPECT_EQ(8000, rpc->msgin.granted);
	EXPECT_STREQ("xmit GRANT 8000@0", unit_log_get());
}
TEST_F(homa_grant, homa_grant_send__nothing_available)
{
	struct homa_rpc *rpc = test_rpc(self, 100, self->server_ip, 20000);
	int granted;

	atomic_set(&self->homa.total_incoming, self->homa.max_incoming);
	unit_log_clear();
	granted = homa_grant_send(rpc, &self->homa);
	EXPECT_EQ(0, granted);
	EXPECT_EQ(0, rpc->msgin.granted);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_grant, homa_grant_send__skip_because_of_silent_ticks)
{
	struct homa_rpc *rpc = test_rpc(self, 100, self->server_ip, 20000);
	int granted;

	rpc->silent_ticks = 2;
	unit_log_clear();
	granted = homa_grant_send(rpc, &self->homa);
	EXPECT_EQ(0, granted);
}
TEST_F(homa_grant, homa_grant_send__resend_all)
{
	struct homa_rpc *rpc = test_rpc(self, 100, self->server_ip, 20000);
	int granted;

	rpc->msgin.resend_all = 1;
	unit_log_clear();
	granted = homa_grant_send(rpc, &self->homa);
	EXPECT_EQ(1, granted);
	EXPECT_EQ(10000, rpc->msgin.granted);
	EXPECT_EQ(0, rpc->msgin.resend_all);
	EXPECT_STREQ("xmit GRANT 10000@0 resend_all", unit_log_get());
}

TEST_F(homa_grant, homa_grant_check_rpc__msgin_not_initialized)
{
	struct homa_rpc *rpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->server_port,
			100, 1000, 2000);

	rpc->msgin.bytes_remaining = 500;
	rpc->msgin.granted = 2000;
	rpc->msgin.rec_incoming = 0;
	homa_grant_check_rpc(rpc);
	EXPECT_EQ(0, rpc->msgin.rec_incoming);
	EXPECT_EQ(0, atomic_read(&self->homa.total_incoming));
}
TEST_F(homa_grant, homa_grant_check_rpc__rpc_dead)
{
	struct homa_rpc *rpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->server_port,
			100, 1000, 2000);
	int old_state;

	homa_message_in_init(rpc, 2000, 0);
	homa_grant_check_rpc(rpc);
	EXPECT_EQ(2000, rpc->msgin.rec_incoming);
	EXPECT_EQ(2000, atomic_read(&self->homa.total_incoming));

	old_state = rpc->state;
	rpc->state = RPC_DEAD;
	rpc->msgin.bytes_remaining = 0;
	homa_grant_check_rpc(rpc);
	rpc->state = old_state;
	EXPECT_EQ(2000, rpc->msgin.rec_incoming);
	EXPECT_EQ(2000, atomic_read(&self->homa.total_incoming));
}
TEST_F(homa_grant, homa_grant_check_rpc__message_doesnt_need_grants)
{
	struct homa_rpc *rpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->server_port,
			100, 1000, 2000);

	homa_message_in_init(rpc, 2000, 0);
	rpc->msgin.granted = 2000;
	rpc->msgin.bytes_remaining = 500;

	homa_grant_check_rpc(rpc);
	EXPECT_EQ(500, rpc->msgin.rec_incoming);
	EXPECT_EQ(500, atomic_read(&self->homa.total_incoming));

	rpc->msgin.bytes_remaining = 0;
	homa_grant_check_rpc(rpc);
	EXPECT_EQ(0, rpc->msgin.rec_incoming);
	EXPECT_EQ(0, atomic_read(&self->homa.total_incoming));
}
TEST_F(homa_grant, homa_grant_check_rpc__add_new_message_to_grantables)
{
	struct homa_rpc *rpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->server_port,
			100, 1000, 20000);

	homa_message_in_init(rpc, 20000, 0);
	rpc->msgin.bytes_remaining = 12000;

	homa_grant_check_rpc(rpc);
	EXPECT_EQ(18000, rpc->msgin.granted);
	EXPECT_EQ(10000, rpc->msgin.rec_incoming);
	EXPECT_EQ(0, atomic_read(&rpc->msgin.rank));
	EXPECT_EQ(10000, atomic_read(&self->homa.total_incoming));
}
TEST_F(homa_grant, homa_grant_check_rpc__new_message_bumps_existing)
{
	struct homa_rpc *rpc1, *rpc2, *rpc3;

	rpc1 = test_rpc(self, 100, self->server_ip, 20000);
	rpc2 = test_rpc(self, 102, self->server_ip, 30000);
	self->homa.max_overcommit = 2;
	homa_grant_recalc(&self->homa, NULL);
	EXPECT_EQ(0, atomic_read(&rpc1->msgin.rank));
	EXPECT_EQ(1, atomic_read(&rpc2->msgin.rank));

	rpc3 = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			self->server_ip, self->server_port, 104, 1000, 25000);
	homa_message_in_init(rpc3, 20000, 0);
	homa_grant_check_rpc(rpc3);
	EXPECT_EQ(10000, rpc3->msgin.granted);
	EXPECT_EQ(10000, rpc3->msgin.rec_incoming);
	EXPECT_EQ(1, atomic_read(&rpc3->msgin.rank));
	EXPECT_EQ(-1, atomic_read(&rpc2->msgin.rank));
	EXPECT_EQ(0, atomic_read(&rpc1->msgin.rank));
}
TEST_F(homa_grant, homa_grant_check_rpc__new_message_cant_be_granted)
{
	struct homa_rpc *rpc1, *rpc2, *rpc3;

	rpc1 = test_rpc(self, 100, self->server_ip, 20000);
	rpc2 = test_rpc(self, 102, self->server_ip, 30000);
	self->homa.max_overcommit = 2;
	homa_grant_recalc(&self->homa, NULL);
	EXPECT_EQ(0, atomic_read(&rpc1->msgin.rank));
	EXPECT_EQ(1, atomic_read(&rpc2->msgin.rank));
	rpc2->msgin.bytes_remaining = 1000;

	rpc3 = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			self->server_ip, self->server_port, 104, 1000, 30000);
	homa_message_in_init(rpc3, 30000, 0);
	homa_grant_check_rpc(rpc3);
	EXPECT_EQ(0, rpc3->msgin.granted);
	EXPECT_EQ(0, rpc3->msgin.rec_incoming);
	EXPECT_EQ(-1, atomic_read(&rpc3->msgin.rank));
	EXPECT_EQ(1, atomic_read(&rpc2->msgin.rank));
	EXPECT_EQ(0, atomic_read(&rpc1->msgin.rank));
}
TEST_F(homa_grant, homa_grant_check_rpc__upgrade_priority_from_negative_rank)
{
	struct homa_rpc *rpc1, *rpc2, *rpc3;

	rpc1 = test_rpc(self, 100, self->server_ip, 20000);
	rpc2 = test_rpc(self, 102, self->server_ip, 30000);
	rpc3 = test_rpc(self, 104, self->server_ip, 40000);
	self->homa.max_overcommit = 2;
	homa_grant_recalc(&self->homa, NULL);
	EXPECT_EQ(0, atomic_read(&rpc1->msgin.rank));
	EXPECT_EQ(1, atomic_read(&rpc2->msgin.rank));
	EXPECT_EQ(-1, atomic_read(&rpc3->msgin.rank));
	EXPECT_EQ(0, rpc3->msgin.granted);

	rpc3->msgin.bytes_remaining = 15000;
	homa_grant_check_rpc(rpc3);
	EXPECT_EQ(35000, rpc3->msgin.granted);
	EXPECT_EQ(10000, rpc3->msgin.rec_incoming);
	EXPECT_EQ(0, atomic_read(&rpc3->msgin.rank));
	EXPECT_EQ(-1, atomic_read(&rpc2->msgin.rank));
	EXPECT_EQ(1, atomic_read(&rpc1->msgin.rank));
}
TEST_F(homa_grant, homa_grant_check_rpc__upgrade_priority_from_positive_rank)
{
	struct homa_rpc *rpc1, *rpc2, *rpc3;

	rpc1 = test_rpc(self, 100, self->server_ip, 20000);
	rpc2 = test_rpc(self, 102, self->server_ip, 30000);
	rpc3 = test_rpc(self, 104, self->server_ip, 40000);
	self->homa.max_overcommit = 4;
	homa_grant_recalc(&self->homa, NULL);
	EXPECT_EQ(0, atomic_read(&rpc1->msgin.rank));
	EXPECT_EQ(1, atomic_read(&rpc2->msgin.rank));
	EXPECT_EQ(2, atomic_read(&rpc3->msgin.rank));
	EXPECT_EQ(10000, rpc3->msgin.granted);

	rpc3->msgin.bytes_remaining = 25000;
	unit_log_clear();
	homa_grant_check_rpc(rpc3);
	EXPECT_EQ(25000, rpc3->msgin.granted);
	EXPECT_EQ(10000, rpc3->msgin.rec_incoming);
	EXPECT_EQ(1, atomic_read(&rpc3->msgin.rank));
	EXPECT_EQ(2, atomic_read(&rpc2->msgin.rank));
	EXPECT_EQ(0, atomic_read(&rpc1->msgin.rank));
	EXPECT_STREQ("xmit GRANT 25000@1", unit_log_get());
}
TEST_F(homa_grant, homa_grant_check_rpc__send_new_grant)
{
	struct homa_rpc *rpc;

	rpc = test_rpc(self, 100, self->server_ip, 40000);
	homa_grant_recalc(&self->homa, NULL);
	EXPECT_EQ(0, atomic_read(&rpc->msgin.rank));
	EXPECT_EQ(10000, rpc->msgin.granted);
	EXPECT_EQ(10000, atomic_read(&self->homa.total_incoming));

	rpc->msgin.bytes_remaining = 35000;
	unit_log_clear();
	homa_grant_check_rpc(rpc);
	EXPECT_EQ(15000, rpc->msgin.granted);
	EXPECT_EQ(10000, rpc->msgin.rec_incoming);
	EXPECT_EQ(10000, atomic_read(&self->homa.total_incoming));
	EXPECT_STREQ("xmit GRANT 15000@0", unit_log_get());
}
TEST_F(homa_grant, homa_grant_check_rpc__remove_from_grantable)
{
	struct homa_rpc *rpc;

	rpc = test_rpc(self, 100, self->server_ip, 40000);
	homa_grant_recalc(&self->homa, NULL);
	EXPECT_EQ(0, atomic_read(&rpc->msgin.rank));
	EXPECT_EQ(10000, rpc->msgin.granted);
	EXPECT_EQ(10000, atomic_read(&self->homa.total_incoming));

	rpc->msgin.bytes_remaining = 10000;
	rpc->msgin.granted = 30000;
	rpc->msgin.rec_incoming = 10000;
	unit_log_clear();
	homa_grant_check_rpc(rpc);
	EXPECT_EQ(40000, rpc->msgin.granted);
	EXPECT_EQ(10000, rpc->msgin.rec_incoming);
	EXPECT_EQ(10000, atomic_read(&self->homa.total_incoming));
	EXPECT_STREQ("xmit GRANT 40000@0", unit_log_get());
	EXPECT_EQ(0, self->homa.num_grantable_rpcs);
	EXPECT_EQ(0, self->homa.num_active_rpcs);
	EXPECT_EQ(-1, atomic_read(&rpc->msgin.rank));
}
TEST_F(homa_grant, homa_grant_check_rpc__recalc_because_of_headroom)
{
	struct homa_rpc *rpc1, *rpc2;

	rpc1 = test_rpc(self, 100, self->server_ip, 20000);
	rpc2 = test_rpc(self, 102, self->server_ip, 30000);
	self->homa.max_incoming = 15000;
	homa_grant_recalc(&self->homa, NULL);
	EXPECT_EQ(15000, atomic_read(&self->homa.total_incoming));
	EXPECT_EQ(10000, rpc1->msgin.granted);
	EXPECT_EQ(5000, rpc2->msgin.granted);

	rpc1->msgin.bytes_remaining = 4000;
	rpc1->msgin.granted = 12000;
	rpc1->msgin.rec_incoming = 10000;
	unit_log_clear();
	homa_grant_check_rpc(rpc1);
	EXPECT_EQ(20000, rpc1->msgin.granted);
	EXPECT_EQ(4000, rpc1->msgin.rec_incoming);
	EXPECT_EQ(10000, rpc2->msgin.granted);
	EXPECT_EQ(10000, rpc2->msgin.rec_incoming);
	EXPECT_STREQ("xmit GRANT 20000@1; xmit GRANT 10000@0", unit_log_get());
	EXPECT_EQ(14000, atomic_read(&self->homa.total_incoming));
}

TEST_F(homa_grant, homa_grant_recalc__basics)
{
	struct homa_rpc *rpc1, *rpc2, *rpc3, *rpc4;

	rpc1 = test_rpc(self, 100, self->server_ip, 20000);
	rpc2 = test_rpc(self, 102, self->server_ip, 30000);
	rpc3 = test_rpc(self, 104, self->server_ip+1, 25000);
	rpc4 = test_rpc(self, 106, self->server_ip+1, 35000);
	self->homa.max_incoming = 100000;
	self->homa.max_overcommit = 3;
	mock_ns_tick = 10;

	unit_log_clear();
	homa_grant_recalc(&self->homa, NULL);
	EXPECT_STREQ("xmit GRANT 10000@2; "
			"xmit GRANT 10000@1; "
			"xmit GRANT 10000@0", unit_log_get());
	EXPECT_EQ(0, atomic_read(&rpc1->msgin.rank));
	EXPECT_EQ(2, rpc1->msgin.priority);
	EXPECT_EQ(10000, rpc1->msgin.granted);
	EXPECT_EQ(20000, atomic_read(&self->homa.active_remaining[0]));
	EXPECT_EQ(1, atomic_read(&self->homa.grant_recalc_count));

	EXPECT_EQ(1, atomic_read(&rpc3->msgin.rank));
	EXPECT_EQ(1, rpc3->msgin.priority);
	EXPECT_EQ(10000, rpc3->msgin.granted);
	EXPECT_EQ(30000, atomic_read(&self->homa.active_remaining[2]));

	EXPECT_EQ(2, atomic_read(&rpc2->msgin.rank));
	EXPECT_EQ(-1, atomic_read(&rpc4->msgin.rank));
	EXPECT_NE(0, homa_metrics_per_cpu()->grant_recalc_ns);
}
TEST_F(homa_grant, homa_grant_recalc__release_parent_rpc_lock)
{
	struct homa_rpc *rpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->server_port,
			100, 1000, 10000);

	homa_rpc_lock(rpc);
	mock_total_spin_locks = 0;
	homa_grant_recalc(&self->homa, NULL);
	EXPECT_EQ(1, mock_total_spin_locks);

	homa_grant_recalc(&self->homa, rpc);
	EXPECT_EQ(3, mock_total_spin_locks);
	homa_rpc_unlock(rpc);
}
TEST_F(homa_grant, homa_grant_recalc__skip_recalc)
{
	struct homa_rpc *rpc = test_rpc(self, 100, self->server_ip, 20000);

	unit_hook_register(grantable_spinlock_hook);
	hook_homa = &self->homa;
	mock_trylock_errors = 0xff;

	unit_log_clear();
	homa_grant_recalc(&self->homa, NULL);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(0, rpc->msgin.granted);
	EXPECT_EQ(2, atomic_read(&self->homa.grant_recalc_count));
	EXPECT_EQ(1, homa_metrics_per_cpu()->grant_recalc_skips);
}
TEST_F(homa_grant, homa_grant_recalc__clear_existing_active_rpcs)
{
	struct homa_rpc *rpc1;

	rpc1 = test_rpc(self, 100, self->server_ip, 40000);
	test_rpc(self, 102, self->server_ip, 30000);
	test_rpc(self, 104, self->server_ip, 25000);
	test_rpc(self, 106, self->server_ip, 35000);
	self->homa.active_rpcs[0] = rpc1;
	atomic_set(&rpc1->msgin.rank, 10);
	self->homa.num_active_rpcs = 1;
	self->homa.max_incoming = 100000;
	self->homa.max_rpcs_per_peer = 10;
	self->homa.max_overcommit = 2;

	homa_grant_recalc(&self->homa, NULL);
	EXPECT_EQ(-1, atomic_read(&rpc1->msgin.rank));
	EXPECT_EQ(2, self->homa.num_active_rpcs);
}
TEST_F(homa_grant, homa_grant_recalc__use_only_lowest_priorities)
{
	struct homa_rpc *rpc1, *rpc2;

	rpc1 = test_rpc(self, 100, self->server_ip, 20000);
	rpc2 = test_rpc(self, 102, self->server_ip, 30000);
	self->homa.max_incoming = 100000;
	self->homa.max_sched_prio = 5;

	unit_log_clear();
	homa_grant_recalc(&self->homa, NULL);
	EXPECT_STREQ("xmit GRANT 10000@1; xmit GRANT 10000@0", unit_log_get());
	EXPECT_EQ(1, rpc1->msgin.priority);
	EXPECT_EQ(0, rpc2->msgin.priority);
}
TEST_F(homa_grant, homa_grant_recalc__share_lowest_priority_level)
{
	struct homa_rpc *rpc1, *rpc2, *rpc3, *rpc4;

	rpc1 = test_rpc(self, 100, self->server_ip, 20000);
	rpc2 = test_rpc(self, 102, self->server_ip, 30000);
	rpc3 = test_rpc(self, 100, self->server_ip, 40000);
	rpc4 = test_rpc(self, 102, self->server_ip, 50000);
	self->homa.max_incoming = 100000;
	self->homa.max_sched_prio = 2;

	unit_log_clear();
	homa_grant_recalc(&self->homa, NULL);
	EXPECT_STREQ("xmit GRANT 10000@2; "
			"xmit GRANT 10000@1; "
			"xmit GRANT 10000@0; "
			"xmit GRANT 10000@0", unit_log_get());
	EXPECT_EQ(2, rpc1->msgin.priority);
	EXPECT_EQ(1, rpc2->msgin.priority);
	EXPECT_EQ(0, rpc3->msgin.priority);
	EXPECT_EQ(0, rpc4->msgin.priority);
}
TEST_F(homa_grant, homa_grant_recalc__compute_window_size)
{
	struct homa_rpc *rpc1, *rpc2, *rpc3;

	rpc1 = test_rpc(self, 100, self->server_ip, 30000);
	rpc2 = test_rpc(self, 102, self->server_ip, 40000);
	rpc3 = test_rpc(self, 100, self->server_ip, 50000);
	self->homa.max_incoming = 100000;

	/* First try: fixed window size. */
	self->homa.window_param = 5000;
	homa_grant_recalc(&self->homa, NULL);
	EXPECT_EQ(5000, self->homa.grant_window);
	EXPECT_EQ(5000, rpc1->msgin.granted);
	EXPECT_EQ(5000, rpc2->msgin.granted);
	EXPECT_EQ(5000, rpc3->msgin.granted);

	/* Second try: dynamic window size. */
	self->homa.window_param = 0;
	homa_grant_recalc(&self->homa, NULL);
	EXPECT_EQ(25000, self->homa.grant_window);
	EXPECT_EQ(25000, rpc1->msgin.granted);
	EXPECT_EQ(25000, rpc2->msgin.granted);
	EXPECT_EQ(25000, rpc3->msgin.granted);
}
TEST_F(homa_grant, homa_grant_recalc__rpc_fully_granted)
{
	struct homa_rpc *rpc1, *rpc2, *rpc3, *rpc4;

	rpc1 = test_rpc(self, 100, self->server_ip, 10000);
	rpc2 = test_rpc(self, 102, self->server_ip, 10000);
	rpc3 = test_rpc(self, 104, self->server_ip, 10000);
	rpc4 = test_rpc(self, 106, self->server_ip, 10000);
	self->homa.max_incoming = 32000;
	self->homa.max_overcommit = 2;

	homa_grant_recalc(&self->homa, NULL);
	EXPECT_EQ(10000, rpc1->msgin.granted);
	EXPECT_EQ(10000, rpc2->msgin.granted);
	EXPECT_EQ(10000, rpc3->msgin.granted);
	EXPECT_EQ(2000, rpc4->msgin.granted);
}
TEST_F(homa_grant, homa_grant_recalc__rpc_fully_granted_but_skip_recalc)
{
	struct homa_rpc *rpc1, *rpc2, *rpc3, *rpc4;

	rpc1 = test_rpc(self, 100, self->server_ip, 10000);
	rpc2 = test_rpc(self, 102, self->server_ip, 10000);
	rpc3 = test_rpc(self, 104, self->server_ip, 10000);
	rpc4 = test_rpc(self, 106, self->server_ip, 10000);
	self->homa.max_incoming = 32000;
	self->homa.max_overcommit = 2;
	unit_hook_register(grantable_spinlock_hook);
	hook_homa = &self->homa;
	mock_trylock_errors = 0xfe0;
	EXPECT_EQ(0, homa_metrics_per_cpu()->grant_recalc_skips);

	homa_grant_recalc(&self->homa, NULL);
	EXPECT_EQ(10000, rpc1->msgin.granted);
	EXPECT_EQ(10000, rpc2->msgin.granted);
	EXPECT_EQ(0, rpc3->msgin.granted);
	EXPECT_EQ(0, rpc4->msgin.granted);
	EXPECT_EQ(1, homa_metrics_per_cpu()->grant_recalc_skips);
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

	count = homa_grant_pick_rpcs(&self->homa, rpcs, 5);
	EXPECT_EQ(4, count);
	EXPECT_STREQ("200 500 300 400", rpc_ids(rpcs, count));
}
TEST_F(homa_grant, homa_grant_pick_rpcs__new_rpc_goes_in_middle_of_list_with_overflow)
{
	struct homa_rpc *rpcs[4];
	int count;

	test_rpc(self, 200, self->server_ip, 20000);
	test_rpc(self, 300, self->server_ip, 30000);
	test_rpc(self, 400, self->server_ip, 40000);
	test_rpc(self, 500, self->server_ip+1, 25000);

	count = homa_grant_pick_rpcs(&self->homa, rpcs, 3);
	EXPECT_EQ(3, count);
	EXPECT_STREQ("200 500 300", rpc_ids(rpcs, count));
}
TEST_F(homa_grant, homa_grant_pick_rpcs__non_first_rpc_of_peer_doesnt_fit)
{
	struct homa_rpc *rpcs[4];
	int count;

	test_rpc(self, 200, self->server_ip, 20000);
	test_rpc(self, 300, self->server_ip, 30000);
	test_rpc(self, 400, self->server_ip, 40000);
	test_rpc(self, 500, self->server_ip, 50000);
	test_rpc(self, 600, self->server_ip+1, 25000);

	self->homa.max_rpcs_per_peer = 3;
	count = homa_grant_pick_rpcs(&self->homa, rpcs, 3);
	EXPECT_EQ(3, count);
	EXPECT_STREQ("200 600 300", rpc_ids(rpcs, count));
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

TEST_F(homa_grant, homa_grant_find_oldest__basics)
{
	mock_ns_tick = 10;
	unit_server_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, self->client_ip,
			self->server_ip, self->client_port, 11, 40000, 100);
	unit_server_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, self->client_ip+1,
			self->server_ip, self->client_port, 33, 30000, 100);
	unit_server_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, self->client_ip,
			self->server_ip, self->client_port, 55, 20000, 100);

	unit_log_clear();
	homa_grant_find_oldest(&self->homa);
	EXPECT_NE(NULL, self->homa.oldest_rpc);
	EXPECT_EQ(11, self->homa.oldest_rpc->id);
}
TEST_F(homa_grant, homa_grant_find_oldest__fifo_grant_unused)
{
	struct homa_rpc *srpc1, *srpc2;

	mock_ns_tick = 10;
	srpc1 = unit_server_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, self->client_ip,
			self->server_ip, self->client_port, 11, 400000, 100);
	srpc2 = unit_server_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, self->client_ip+1,
			self->server_ip, self->client_port, 33, 300000, 100);
	unit_server_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, self->client_ip,
			self->server_ip, self->client_port, 55, 200000, 100);
	ASSERT_NE(NULL, srpc1);
	ASSERT_NE(NULL, srpc2);
	srpc1->msgin.granted += + 2*self->homa.fifo_grant_increment;

	unit_log_clear();
	homa_grant_find_oldest(&self->homa);
	EXPECT_NE(NULL, self->homa.oldest_rpc);
	EXPECT_EQ(33, self->homa.oldest_rpc->id);
}
TEST_F(homa_grant, homa_grant_find_oldest__no_good_candidates)
{
	homa_grant_find_oldest(&self->homa);
	EXPECT_EQ(NULL, self->homa.oldest_rpc);
}

TEST_F(homa_grant, homa_grant_rpc_free__rpc_not_grantable)
{
	struct homa_rpc *rpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->server_port,
			100, 1000, 2000);
	atomic_set(&self->homa.total_incoming, 10000);
	rpc->msgin.rec_incoming = 3000;
	homa_grant_free_rpc(rpc);
	EXPECT_EQ(7000, atomic_read(&self->homa.total_incoming));
}
TEST_F(homa_grant, homa_grant_free_rpc__in_active_list)
{
	struct homa_rpc *rpc1, *rpc2, *rpc3;

	rpc1 = test_rpc(self, 100, self->server_ip, 20000);
	rpc2 = test_rpc(self, 102, self->server_ip, 30000);
	rpc3 = test_rpc(self, 104, self->server_ip, 40000);
	self->homa.max_overcommit = 2;
	homa_grant_recalc(&self->homa, NULL);
	EXPECT_EQ(0, atomic_read(&rpc1->msgin.rank));
	EXPECT_EQ(1, atomic_read(&rpc2->msgin.rank));
	EXPECT_EQ(-1, atomic_read(&rpc3->msgin.rank));
	EXPECT_EQ(20000, atomic_read(&self->homa.total_incoming));
	EXPECT_EQ(10000, rpc1->msgin.rec_incoming);

	unit_log_clear();
	homa_grant_free_rpc(rpc1);
	EXPECT_EQ(-1, atomic_read(&rpc1->msgin.rank));
	EXPECT_EQ(0, atomic_read(&rpc2->msgin.rank));
	EXPECT_EQ(1, atomic_read(&rpc3->msgin.rank));
	EXPECT_EQ(20000, atomic_read(&self->homa.total_incoming));
}
TEST_F(homa_grant, homa_grant_free_rpc__not_in_active_list)
{
	struct homa_rpc *rpc1, *rpc2, *rpc3;

	rpc1 = test_rpc(self, 100, self->server_ip, 20000);
	rpc2 = test_rpc(self, 102, self->server_ip, 30000);
	rpc3 = test_rpc(self, 104, self->server_ip, 40000);
	self->homa.max_overcommit = 2;
	homa_grant_recalc(&self->homa, NULL);
	EXPECT_EQ(0, atomic_read(&rpc1->msgin.rank));
	EXPECT_EQ(1, atomic_read(&rpc2->msgin.rank));
	EXPECT_EQ(-1, atomic_read(&rpc3->msgin.rank));
	EXPECT_EQ(20000, atomic_read(&self->homa.total_incoming));
	EXPECT_EQ(0, rpc3->msgin.rec_incoming);
	EXPECT_FALSE(list_empty(&rpc3->grantable_links));

	rpc3->msgin.rec_incoming = 5000;
	homa_grant_free_rpc(rpc3);
	EXPECT_TRUE(list_empty(&rpc3->grantable_links));
	EXPECT_EQ(15000, atomic_read(&self->homa.total_incoming));
}

TEST_F(homa_grant, homa_grantable_lock_slow__basics)
{
	mock_ns = 500;
	unit_hook_register(grantable_spinlock_hook);

	EXPECT_EQ(1, homa_grantable_lock_slow(&self->homa, 0));
	homa_grantable_unlock(&self->homa);

	EXPECT_EQ(1, homa_metrics_per_cpu()->grantable_lock_misses);
	EXPECT_EQ(500, homa_metrics_per_cpu()->grantable_lock_miss_ns);
}
TEST_F(homa_grant, homa_grantable_lock_slow__recalc_count)
{
	mock_ns = 500;
	unit_hook_register(grantable_spinlock_hook);
	hook_homa = &self->homa;
	mock_trylock_errors = 0xff;

	EXPECT_EQ(0, homa_grantable_lock_slow(&self->homa, 1));
	hook_homa = NULL;

	EXPECT_EQ(1, homa_metrics_per_cpu()->grantable_lock_misses);
	EXPECT_EQ(500, homa_metrics_per_cpu()->grantable_lock_miss_ns);

	/* Make sure the check only occurs if the recalc argument is set. */
	mock_trylock_errors = 0xff;
	EXPECT_EQ(1, homa_grantable_lock_slow(&self->homa, 0));
	EXPECT_EQ(2, homa_metrics_per_cpu()->grantable_lock_misses);
	homa_grantable_unlock(&self->homa);
}
