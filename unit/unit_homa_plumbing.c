#include "homa_impl.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

#define n(x) htons(x)
#define N(x) htonl(x)

FIXTURE(homa_plumbing) {
	struct homa homa;
	struct homa_sock hsk;
	__be32 client_ip;
	__be32 server_ip;
	struct sockaddr_in server_addr;
	struct data_header data;
	int starting_skb_count;
};
FIXTURE_SETUP(homa_plumbing)
{
	homa = &self->homa;
	homa_init(&self->homa);
	mock_sock_init(&self->hsk, &self->homa);
	homa_sock_bind(&self->homa.port_map, &self->hsk, 99);
	self->client_ip = unit_get_in_addr("196.168.0.1");
	self->server_ip = unit_get_in_addr("1.2.3.4");
	self->server_addr.sin_family = AF_INET;
	self->server_addr.sin_addr.s_addr = self->server_ip;
	self->server_addr.sin_port = htons(99);
	self->data = (struct data_header){.common = {.sport = n(5),
	                .dport = n(99), .id = 12345, .type = DATA},
		        .message_length = N(10000), .offset = 0,
			.unscheduled = N(10000), .retransmit = 0};
	unit_log_clear();
}
FIXTURE_TEARDOWN(homa_plumbing)
{
	mock_sock_destroy(&self->hsk, &self->homa.port_map);
	homa_destroy(&self->homa);
	unit_teardown();
	homa = NULL;
}

TEST_F(homa_plumbing, homa_pkt_recv__packet_too_short)
{
	struct sk_buff *skb;
	skb = mock_skb_new(self->client_ip, &self->data.common, 1400, 1400);
	skb->len = 12;
	homa_pkt_recv(skb);
	EXPECT_EQ(0, unit_list_length(&self->hsk.server_rpcs));
}
TEST_F(homa_plumbing, homa_pkt_recv__unknown_socket)
{
	struct sk_buff *skb;
	self->data.common.dport = 100;
	skb = mock_skb_new(self->client_ip, &self->data.common, 1400, 1400);
	homa_pkt_recv(skb);
	EXPECT_EQ(0, unit_list_length(&self->hsk.server_rpcs));
}
TEST_F(homa_plumbing, homa_pkt_recv__use_backlog)
{
	struct sk_buff *skb;
	lock_sock((struct sock *) &self->hsk);
	skb = mock_skb_new(self->client_ip, &self->data.common, 1400, 1400);
	EXPECT_EQ(NULL, self->hsk.inet.sk.sk_backlog.head);
	homa_pkt_recv(skb);
	EXPECT_EQ(0, unit_list_length(&self->hsk.server_rpcs));
	EXPECT_EQ(skb, self->hsk.inet.sk.sk_backlog.head);
	kfree_skb(self->hsk.inet.sk.sk_backlog.head);
	release_sock((struct sock *) &self->hsk);
}