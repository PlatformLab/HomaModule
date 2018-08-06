#include "homa_impl.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

FIXTURE(homa_output) {
	struct homa homa;
	struct homa_sock hsk;
	__be32 client_ip;
	__be32 server_ip;
	struct sockaddr_in server_addr;
};
FIXTURE_SETUP(homa_output)
{
	homa_init(&self->homa);
	mock_sock_init(&self->hsk, &self->homa);
	self->client_ip = unit_get_in_addr("196.168.0.1");
	self->server_ip = unit_get_in_addr("1.2.3.4");
	self->server_addr.sin_family = AF_INET;
	self->server_addr.sin_addr.s_addr = self->server_ip;
	self->server_addr.sin_port = htons(99);
	unit_log_clear();
}
FIXTURE_TEARDOWN(homa_output)
{
	mock_sock_destroy(&self->hsk);
	homa_destroy(&homa);
	unit_teardown();
}

TEST_F(homa_output, homa_message_out_init_basics)
{
	int err;
	struct homa_client_rpc *crpc = homa_client_rpc_new(&self->hsk,
			&self->server_addr, 3000, NULL, &err);
	EXPECT_EQ(1, unit_list_length(&self->hsk.client_rpcs));
	EXPECT_EQ(0, err);
	EXPECT_STREQ("csum_and_copy_from_iter_full copied 1400 bytes; "
		"csum_and_copy_from_iter_full copied 1400 bytes; "
		"csum_and_copy_from_iter_full copied 200 bytes", unit_log_get());
	unit_log_clear();
	unit_log_message_out_packets(&crpc->request, 1);
	EXPECT_STREQ("DATA from 0.0.0.0:32768, id 1, length 1426, "
			"message_length 3000, offset 0, unscheduled 9800; "
		     "DATA from 0.0.0.0:32768, id 1, length 1426, "
			"message_length 3000, offset 1400, unscheduled 9800; "
		     "DATA from 0.0.0.0:32768, id 1, length 226, "
			"message_length 3000, offset 2800, unscheduled 9800",
		     unit_log_get());
}

TEST_F(homa_output, homa_message_out_init__cant_alloc_skb)
{
	int err;
	mock_alloc_skb_errors = 2;
	struct homa_client_rpc *crpc = homa_client_rpc_new(&self->hsk,
			&self->server_addr, 3000, NULL, &err);
	EXPECT_EQ(0, unit_list_length(&self->hsk.client_rpcs));
	EXPECT_EQ(ENOMEM, -err);
	EXPECT_EQ(crpc, NULL);
}

TEST_F(homa_output, homa_message_out_init__cant_copy_data)
{
	int err;
	mock_copy_data_errors = 2;
	struct homa_client_rpc *crpc = homa_client_rpc_new(&self->hsk,
			&self->server_addr, 3000, NULL, &err);
	EXPECT_EQ(0, unit_list_length(&self->hsk.client_rpcs));
	EXPECT_EQ(EFAULT, -err);
	EXPECT_EQ(crpc, NULL);
}