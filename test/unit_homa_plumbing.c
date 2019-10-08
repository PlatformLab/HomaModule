#include "homa_impl.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

extern struct homa *homa;

FIXTURE(homa_plumbing) {
	__be32 client_ip;
	int client_port;
	__be32 server_ip;
	int server_port;
	__u64 rpcid;
	struct homa homa;
	struct homa_sock hsk;
	struct sockaddr_in server_addr;
	struct data_header data;
	int starting_skb_count;
};
FIXTURE_SETUP(homa_plumbing)
{
	self->client_ip = unit_get_in_addr("196.168.0.1");
	self->client_port = 40000;
	self->server_ip = unit_get_in_addr("1.2.3.4");
	self->server_port = 99;
	self->rpcid = 12345;
	self->server_addr.sin_family = AF_INET;
	self->server_addr.sin_addr.s_addr = self->server_ip;
	self->server_addr.sin_port = htons(self->server_port);
	homa = &self->homa;
	homa_init(&self->homa);
	mock_sock_init(&self->hsk, &self->homa, 0, 0);
	homa_sock_bind(&self->homa.port_map, &self->hsk, self->server_port);
	self->data = (struct data_header){.common = {
			.sport = htons(self->client_port),
	                .dport = htons(self->server_port),
			.type = DATA, .id = self->rpcid},
			.message_length = htonl(10000),
			.incoming = htonl(10000), .retransmit = 0,
			.seg={.offset = 0}};
	unit_log_clear();
}
FIXTURE_TEARDOWN(homa_plumbing)
{
	homa_destroy(&self->homa);
	unit_teardown();
	homa = NULL;
}

TEST_F(homa_plumbing, homa_pkt_recv__basics)
{
	struct sk_buff *skb;
	skb = mock_skb_new(self->client_ip, &self->data.common, 1400, 1400);
	homa_pkt_recv(skb);
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
}
TEST_F(homa_plumbing, homa_pkt_recv__packet_too_short)
{
	struct sk_buff *skb;
	skb = mock_skb_new(self->client_ip, &self->data.common, 1400, 1400);
	skb->len = 12;
	homa_pkt_recv(skb);
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
}
TEST_F(homa_plumbing, homa_pkt_recv__cant_pull_header)
{
	struct sk_buff *skb;
	skb = mock_skb_new(self->client_ip, &self->data.common, 1400, 1400);
	skb->data_len = skb->len - 20;
	homa_pkt_recv(skb);
	EXPECT_STREQ("pskb discard", unit_log_get());
}
TEST_F(homa_plumbing, homa_pkt_recv__remove_extra_headers)
{
	struct sk_buff *skb;
	skb = mock_skb_new(self->client_ip, &self->data.common, 1400, 1400);
	__skb_push(skb, 10);
	homa_pkt_recv(skb);
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
}
TEST_F(homa_plumbing, homa_pkt_recv__unknown_socket)
{
	struct sk_buff *skb;
	self->data.common.dport = htons(100);
	skb = mock_skb_new(self->client_ip, &self->data.common, 1400, 1400);
	homa_pkt_recv(skb);
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
}
TEST_F(homa_plumbing, homa_pkt_recv__multiple_packets_different_sockets)
{
	struct sk_buff *skb, *skb2;
	struct homa_sock sock2;
	mock_sock_init(&sock2, &self->homa, 0, 0);
	homa_sock_bind(&self->homa.port_map, &sock2, self->server_port+1);
	
	skb = mock_skb_new(self->client_ip, &self->data.common, 1400, 1400);
	self->data.common.dport = htons(self->server_port+1);
	skb2 = mock_skb_new(self->client_ip, &self->data.common, 1400, 1400);
	skb_shinfo(skb)->frag_list = skb2;
	skb2->next = NULL;
	homa_pkt_recv(skb);
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_EQ(1, unit_list_length(&sock2.active_rpcs));
	homa_sock_destroy(&sock2);
}
TEST_F(homa_plumbing, homa_pkt_recv__multiple_packets_same_socket)
{
	struct sk_buff *skb, *skb2;
	skb = mock_skb_new(self->client_ip, &self->data.common, 1400, 1400);
	self->data.common.id += 1;
	skb2 = mock_skb_new(self->client_ip, &self->data.common, 1400, 1400);
	skb_shinfo(skb)->frag_list = skb2;
	skb2->next = NULL;
	homa_pkt_recv(skb);
	EXPECT_EQ(2, unit_list_length(&self->hsk.active_rpcs));
}
TEST_F(homa_plumbing, homa_pkt_recv__use_backlog)
{
	struct sk_buff *skb;
	lock_sock((struct sock *) &self->hsk);
	skb = mock_skb_new(self->client_ip, &self->data.common, 1400, 1400);
	EXPECT_EQ(NULL, self->hsk.inet.sk.sk_backlog.head);
	homa_pkt_recv(skb);
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_EQ(skb, self->hsk.inet.sk.sk_backlog.head);
	kfree_skb(self->hsk.inet.sk.sk_backlog.head);
	release_sock((struct sock *) &self->hsk);
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
	loff_t offset = 10;
	self->homa.metrics = kmalloc(100, GFP_KERNEL);
	self->homa.metrics_capacity = 100;
	strcpy(self->homa.metrics, "0123456789abcdefghijklmnop");
	self->homa.metrics_length = 26;
	EXPECT_EQ(5, homa_metrics_read(NULL, (char *) 100, 5, &offset));
	EXPECT_STREQ("_copy_to_user copied 5 bytes",
		     unit_log_get());
	EXPECT_EQ(15, offset);
	
	unit_log_clear();
	EXPECT_EQ(11, homa_metrics_read(NULL, (char *) 100, 1000, &offset));
	EXPECT_STREQ("_copy_to_user copied 11 bytes",
		     unit_log_get());
	EXPECT_EQ(26, offset);
	
	unit_log_clear();
	EXPECT_EQ(0, homa_metrics_read(NULL, (char *) 100, 1000, &offset));
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(26, offset);
}
TEST_F(homa_plumbing, homa_metrics_read__error_copying_to_user)
{
	loff_t offset = 10;
	self->homa.metrics = kmalloc(100, GFP_KERNEL);
	self->homa.metrics_capacity = 100;
	strcpy(self->homa.metrics, "0123456789abcdefghijklmnop");
	self->homa.metrics_length = 26;
	mock_copy_to_user_errors = 1;
	EXPECT_EQ(EFAULT, -homa_metrics_read(NULL, (char *) 100, 5, &offset));
}

TEST_F(homa_plumbing, homa_metrics_release)
{
	self->homa.metrics_active_opens = 2;
	EXPECT_EQ(0, homa_metrics_release(NULL, NULL));
	EXPECT_EQ(1, self->homa.metrics_active_opens);
	
	EXPECT_EQ(0, homa_metrics_release(NULL, NULL));
	EXPECT_EQ(0, self->homa.metrics_active_opens);
}