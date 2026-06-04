// SPDX-License-Identifier: BSD-2-Clause or GPL-2.0+

#include "homa_impl.h"
#include "homa_interest.h"
#include "homa_sock.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

#define n(x) htons(x)
#define N(x) htonl(x)

struct homa_sock *hook_hsk;
static int hook_count;
static void schedule_hook(char *id)
{
	if (strcmp(id, "schedule_timeout") != 0)
		return;
	if (hook_count <= 0)
		return;
	hook_count--;
	if (hook_count != 0)
		return;
	hook_hsk->sock.sk_sndbuf = refcount_read(&hook_hsk->sock.sk_wmem_alloc)
				   + 100;
}

static void shutdown_hook(char *id)
{
	if (strcmp(id, "prepare_to_wait") != 0)
		return;
	homa_sock_shutdown(hook_hsk);
}

FIXTURE(homa_sock) {
	struct homa homa;
	struct homa_net *hnet;
	struct homa_sock hsk;
	struct in6_addr client_ip[1];
	int client_port;
	struct in6_addr server_ip[1];
	int server_port;
	u64 client_id;
};
FIXTURE_SETUP(homa_sock)
{
	homa_init(&self->homa);
	self->hnet = mock_hnet(0, &self->homa);
	mock_sock_init(&self->hsk, self->hnet, 0);
	self->client_ip[0] = unit_get_in_addr("196.168.0.1");
	self->client_port = 40000;
	self->server_ip[0] = unit_get_in_addr("1.2.3.4");
	self->server_port = 99;
	self->client_id = 1234;
	unit_log_clear();
}
FIXTURE_TEARDOWN(homa_sock)
{
	homa_destroy(&self->homa);
	unit_teardown();
}

TEST_F(homa_sock, homa_socktab_destroy)
{
	struct homa_sock hsk1, hsk2, hsk3;
	struct homa_net *hnet;

	hnet = mock_hnet(1, &self->homa);
	mock_sock_init(&hsk1, hnet, 100);
	mock_sock_init(&hsk2, hnet, 101);
	mock_sock_init(&hsk3, self->hnet, 100);
	EXPECT_EQ(0, hsk1.shutdown);
	EXPECT_EQ(0, hsk2.shutdown);
	EXPECT_EQ(0, hsk3.shutdown);

	homa_socktab_destroy(self->homa.socktab, hnet);
	EXPECT_EQ(1, hsk1.shutdown);
	EXPECT_EQ(1, hsk2.shutdown);
	EXPECT_EQ(0, hsk3.shutdown);

	homa_socktab_destroy(self->homa.socktab, NULL);
	EXPECT_EQ(1, hsk3.shutdown);
}

TEST_F(homa_sock, homa_socktab_start_scan)
{
	struct homa_socktab_scan scan;

	homa_destroy(&self->homa);
	homa_init(&self->homa);
	mock_sock_init(&self->hsk, self->hnet, HOMA_MIN_DEFAULT_PORT + 100);
	EXPECT_EQ(&self->hsk, homa_socktab_start_scan(self->homa.socktab,
			&scan));
	EXPECT_EQ(100, scan.current_bucket);
	EXPECT_EQ(1, mock_sock_holds);
	homa_socktab_end_scan(&scan);
}

TEST_F(homa_sock, homa_socktab_next__no_sockets)
{
	struct homa_socktab_scan scan;

	homa_destroy(&self->homa);
	homa_init(&self->homa);
	EXPECT_EQ(NULL, homa_socktab_start_scan(self->homa.socktab, &scan));
}
TEST_F(homa_sock, homa_socktab_next__iteration_basics)
{
	struct homa_sock hsk1, hsk2, hsk3, hsk4, *hsk;
	struct homa_socktab_scan scan;
	int first_port = 34000;
	int bucket;

	homa_destroy(&self->homa);
	homa_init(&self->homa);
	mock_sock_init(&hsk1, self->hnet, first_port);
	mock_sock_init(&hsk2, self->hnet, first_port + HOMA_SOCKTAB_BUCKETS);
	mock_sock_init(&hsk3, self->hnet, first_port + 2 * HOMA_SOCKTAB_BUCKETS);
	mock_sock_init(&hsk4, self->hnet, first_port + 5);
	hsk = homa_socktab_start_scan(self->homa.socktab, &scan);
	EXPECT_EQ(first_port + 2 * HOMA_SOCKTAB_BUCKETS, hsk->port);
	EXPECT_EQ(1, mock_sock_holds);
	bucket = scan.current_bucket;

	hsk = homa_socktab_next(&scan);
	EXPECT_EQ(first_port + HOMA_SOCKTAB_BUCKETS, hsk->port);
	EXPECT_EQ(1, mock_sock_holds);
	EXPECT_EQ(bucket, scan.current_bucket);

	hsk = homa_socktab_next(&scan);
	EXPECT_EQ(first_port, hsk->port);
	EXPECT_EQ(1, mock_sock_holds);
	EXPECT_EQ(bucket, scan.current_bucket);

	hsk = homa_socktab_next(&scan);
	EXPECT_EQ(first_port+5, hsk->port);
	EXPECT_EQ(1, mock_sock_holds);
	EXPECT_NE(bucket, scan.current_bucket);
	bucket = scan.current_bucket;

	hsk = homa_socktab_next(&scan);
	EXPECT_EQ(NULL, hsk);
	EXPECT_EQ(0, mock_sock_holds);
	EXPECT_NE(bucket, scan.current_bucket);
	homa_socktab_end_scan(&scan);
	unit_sock_destroy(&hsk1);
	unit_sock_destroy(&hsk2);
	unit_sock_destroy(&hsk3);
	unit_sock_destroy(&hsk4);
}
TEST_F(homa_sock, homa_socktab_next__skip_if_hsk_null_in_slink)
{
	struct homa_socktab_scan scan;
	struct homa_sock hsk1, *hsk;

	homa_destroy(&self->homa);
	homa_init(&self->homa);
	mock_sock_init(&hsk1, self->hnet, 34000);
	EXPECT_EQ(&hsk1, hsk1.slink->hsk);

	/* First scan: pointer is NULL. */
	hsk1.slink->hsk = NULL;
	hsk = homa_socktab_start_scan(self->homa.socktab, &scan);
	EXPECT_EQ(NULL, hsk);
	homa_socktab_end_scan(&scan);

	/* Second scan: pointer not NULL. */
	hsk1.slink->hsk = &hsk1;
	hsk = homa_socktab_start_scan(self->homa.socktab, &scan);
	EXPECT_EQ(&hsk1, hsk);
	homa_socktab_end_scan(&scan);
	unit_sock_destroy(&hsk1);
}
TEST_F(homa_sock, homa_socktab_next__skip_if_refcount_zero)
{
	struct homa_socktab_scan scan;
	struct homa_sock hsk1, *hsk;
	int saved_refcnt;

	homa_destroy(&self->homa);
	homa_init(&self->homa);
	mock_sock_init(&hsk1, self->hnet, 34000);

	/* First scan: reference count is zero. */
	saved_refcnt = atomic_read(&hsk1.sock.sk_refcnt.refs);
	atomic_set(&hsk1.sock.sk_refcnt.refs, 0);
	hsk = homa_socktab_start_scan(self->homa.socktab, &scan);
	EXPECT_EQ(NULL, hsk);
	homa_socktab_end_scan(&scan);

	/* Second scan: reference count nonzero. */
	atomic_set(&hsk1.sock.sk_refcnt.refs, saved_refcnt);
	hsk = homa_socktab_start_scan(self->homa.socktab, &scan);
	EXPECT_NE(NULL, hsk);
	homa_socktab_end_scan(&scan);
	unit_sock_destroy(&hsk1);
}

TEST_F(homa_sock, homa_socktab_end_scan)
{
	struct homa_socktab_scan scan1, scan2, scan3;

	homa_destroy(&self->homa);
	homa_init(&self->homa);
	mock_sock_init(&self->hsk, self->hnet, HOMA_MIN_DEFAULT_PORT+100);
	homa_socktab_start_scan(self->homa.socktab, &scan1);
	homa_socktab_start_scan(self->homa.socktab, &scan2);
	homa_socktab_start_scan(self->homa.socktab, &scan3);
	EXPECT_EQ(3, mock_sock_holds);
	homa_socktab_next(&scan2);
	EXPECT_EQ(2, mock_sock_holds);
	homa_socktab_end_scan(&scan1);
	EXPECT_EQ(1, mock_sock_holds);
	homa_socktab_end_scan(&scan2);
	EXPECT_EQ(1, mock_sock_holds);
	homa_socktab_end_scan(&scan3);
	EXPECT_EQ(0, mock_sock_holds);
}

TEST_F(homa_sock, homa_sock_init__cant_allocate_buffer_pool)
{
	struct homa_sock sock;

	mock_kmalloc_errors = 1;
	EXPECT_EQ(ENOMEM, -mock_sock_init(&sock, self->hnet, 0));
	unit_sock_destroy(&sock);
}
TEST_F(homa_sock, homa_sock_init__skip_port_in_use)
{
	struct homa_sock hsk2, hsk3;

	self->hnet->prev_default_port = 0xfffe;
	mock_sock_init(&hsk2, self->hnet, 0);
	mock_sock_init(&hsk3, self->hnet, 0);
	EXPECT_EQ(65535, hsk2.port);
	EXPECT_EQ(32769, hsk3.port);
	unit_sock_destroy(&hsk2);
	unit_sock_destroy(&hsk3);
}
TEST_F(homa_sock, homa_sock_init__all_ports_in_use)
{
	struct homa_sock hsk2, hsk3, hsk4;

	mock_min_default_port = -2;
	EXPECT_EQ(0, -mock_sock_init(&hsk2, self->hnet, 0));
	EXPECT_EQ(0, -mock_sock_init(&hsk3, self->hnet, 0));
	EXPECT_EQ(EADDRNOTAVAIL, -mock_sock_init(&hsk4, self->hnet, 0));
	EXPECT_EQ(65534, hsk2.port);
	EXPECT_EQ(65535, hsk3.port);
	EXPECT_EQ(1, hsk4.shutdown);
	unit_sock_destroy(&hsk2);
	unit_sock_destroy(&hsk3);
	unit_sock_destroy(&hsk4);
}
TEST_F(homa_sock, homa_sock_init__ip_header_length)
{
	struct homa_sock hsk_v4, hsk_v6;

	mock_ipv6 = false;
	mock_sock_init(&hsk_v4, self->hnet, 0);
	mock_ipv6 = true;
	mock_sock_init(&hsk_v6, self->hnet, 0);
	EXPECT_EQ(sizeof(struct iphdr), hsk_v4.ip_header_length);
	EXPECT_EQ(sizeof(struct ipv6hdr), hsk_v6.ip_header_length);
	unit_sock_destroy(&hsk_v4);
	unit_sock_destroy(&hsk_v6);
}
#ifndef __STRIP__ /* See strip.py */
TEST_F(homa_sock, homa_sock_init__hijack_tcp)
{
	struct homa_sock hijack, no_hijack;

	self->homa.hijack_tcp = 0;
	mock_sock_init(&no_hijack, self->hnet, 0);
	self->homa.hijack_tcp = 1;
	mock_sock_init(&hijack, self->hnet, 0);
	EXPECT_EQ(IPPROTO_HOMA, no_hijack.sock.sk_protocol);
	EXPECT_EQ(IPPROTO_TCP, hijack.sock.sk_protocol);
	unit_sock_destroy(&hijack);
	unit_sock_destroy(&no_hijack);
}
#endif /* See strip.py */

TEST_F(homa_sock, homa_sock_link__basics)
{
	struct homa_sock hsk;
	struct homa_sock_link *slink;

	/* Create initial linking. */
	mock_sock_init(&hsk, self->hnet, 10);
	slink = hsk.slink;
	ASSERT_NE(NULL, slink);
	EXPECT_EQ(&hsk.slink->links, self->homa.socktab->buckets[10].first);
	EXPECT_EQ(&hsk, hsk.slink->hsk);

	/* Change port number for socket, which requires new link. */
	EXPECT_EQ(0, -homa_sock_link(&hsk, 12));
	EXPECT_NE(slink, hsk.slink);
	EXPECT_EQ(NULL, self->homa.socktab->buckets[10].first);
	EXPECT_NE(NULL, self->homa.socktab->buckets[12].first);
	EXPECT_EQ(12, hsk.port);
	EXPECT_EQ(12, hsk.inet.inet_num);

	homa_sock_destroy(&hsk.sock);
}
TEST_F(homa_sock, homa_sock_link__malloc_error)
{
	struct homa_sock hsk;
	struct homa_sock_link *slink;

	mock_sock_init(&hsk, self->hnet, 10);
	slink = hsk.slink;

	mock_kmalloc_errors = 1;
	EXPECT_EQ(ENOMEM, -homa_sock_link(&hsk, 12));
	EXPECT_EQ(slink, hsk.slink);
	EXPECT_NE(NULL, self->homa.socktab->buckets[10].first);
	EXPECT_EQ(NULL, self->homa.socktab->buckets[12].first);
	EXPECT_EQ(10, hsk.port);

	homa_sock_destroy(&hsk.sock);
}

TEST_F(homa_sock, homa_sock_unlink)
{
	struct homa_sock hsk2, hsk3;
	int client2, client3;

	mock_sock_init(&hsk2, self->hnet, 0);
	EXPECT_EQ(0, homa_sock_bind(self->hnet, &hsk2, 100));
	client2 = hsk2.port;
	mock_sock_init(&hsk3, self->hnet, 0);
	client3 = hsk3.port;

	EXPECT_EQ(&hsk2, homa_sock_find(self->hnet, client2));
	EXPECT_EQ(&hsk3, homa_sock_find(self->hnet, client3));
	sock_put(&hsk2.sock);
	sock_put(&hsk3.sock);

	unit_sock_destroy(&hsk2);

	EXPECT_EQ(NULL, homa_sock_find(self->hnet, client2));
	EXPECT_EQ(&hsk3, homa_sock_find(self->hnet, client3));
	sock_put(&hsk3.sock);

	unit_sock_destroy(&hsk3);

	EXPECT_EQ(NULL, homa_sock_find(self->hnet, client2));
	EXPECT_EQ(NULL, homa_sock_find(self->hnet, client3));
}

TEST_F(homa_sock, homa_sock_shutdown__unlink_socket)
{
	struct homa_sock hsk;
	int client;

	mock_sock_init(&hsk, self->hnet, 0);
	EXPECT_EQ(0, homa_sock_bind(self->hnet, &hsk, 100));
	client = hsk.port;
	EXPECT_EQ(&hsk, homa_sock_find(self->hnet, client));
	sock_put(&hsk.sock);

	homa_sock_shutdown(&hsk);
	EXPECT_EQ(NULL, homa_sock_find(self->hnet, client));
	homa_sock_destroy(&hsk.sock);
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
	EXPECT_EQ(2, unit_list_length(&self->hsk.active_rpcs));
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
	homa_sock_destroy(&self->hsk.sock);
}
TEST_F(homa_sock, homa_sock_shutdown__wakeup_interests_and_wmem)
{
	struct homa_interest interest1, interest2;

	mock_log_wakeups = 1;
	homa_interest_init_shared(&interest1, &self->hsk);
	homa_interest_init_shared(&interest2, &self->hsk);
	unit_log_clear();

	homa_sock_shutdown(&self->hsk);
	EXPECT_TRUE(self->hsk.shutdown);
	EXPECT_EQ(HOMA_INTEREST_READY, atomic_read(&interest1.state));
	EXPECT_EQ(HOMA_INTEREST_READY, atomic_read(&interest2.state));
	EXPECT_EQ(NULL, interest1.rpc);
	EXPECT_EQ(NULL, interest2.rpc);
	EXPECT_TRUE(list_empty(&interest1.links));
	EXPECT_STREQ("wake_up; wake_up; wake_up", unit_log_get());
	homa_sock_destroy(&self->hsk.sock);
}

TEST_F(homa_sock, homa_sock_bind)
{
	struct homa_sock hsk2;

	mock_sock_init(&hsk2, self->hnet, 0);
	EXPECT_EQ(0, homa_sock_bind(self->hnet, &hsk2, 100));

	EXPECT_EQ(0, -homa_sock_bind(self->hnet, &self->hsk, 0));
	EXPECT_EQ(HOMA_MIN_DEFAULT_PORT, self->hsk.port);
	EXPECT_EQ(EINVAL, -homa_sock_bind(self->hnet, &self->hsk,
			HOMA_MIN_DEFAULT_PORT + 100));
	EXPECT_STREQ("port number invalid: in the automatically assigned range",
		     self->hsk.error_msg);

	EXPECT_EQ(EADDRINUSE, -homa_sock_bind(self->hnet, &self->hsk, 100));
	EXPECT_STREQ("requested port number is already in use",
		     self->hsk.error_msg);
	EXPECT_EQ(0, -homa_sock_bind(self->hnet, &hsk2, 100));

	EXPECT_EQ(0, -homa_sock_bind(self->hnet, &self->hsk, 110));

	EXPECT_EQ(&self->hsk, homa_sock_find(self->hnet, 110));
	sock_put(&self->hsk.sock);
	EXPECT_EQ(0, -homa_sock_bind(self->hnet, &self->hsk, 120));
	EXPECT_EQ(NULL, homa_sock_find(self->hnet, 110));
	EXPECT_EQ(&self->hsk, homa_sock_find(self->hnet, 120));
	sock_put(&self->hsk.sock);
	unit_sock_destroy(&hsk2);
}
TEST_F(homa_sock, homa_sock_bind__socket_shutdown)
{
	unit_sock_destroy(&self->hsk);
	EXPECT_EQ(ESHUTDOWN, -homa_sock_bind(self->hnet, &self->hsk, 100));
	EXPECT_STREQ("socket has been shut down", self->hsk.error_msg);
}
TEST_F(homa_sock, homa_sock_bind__error_in_homa_sock_link)
{
	struct homa_sock hsk;

	mock_sock_init(&hsk, self->hnet, 10);
	hsk.is_server = false;
	mock_kmalloc_errors = 1;
	EXPECT_EQ(ENOMEM, -homa_sock_bind(hsk.hnet, &hsk, 12));
	EXPECT_EQ(10, hsk.port);
	EXPECT_EQ(0, hsk.is_server);

	homa_sock_destroy(&hsk.sock);
}

TEST_F(homa_sock, homa_sock_find__basics)
{
	struct homa_sock hsk2;

	mock_sock_init(&hsk2, self->hnet, 0);
	EXPECT_EQ(0, homa_sock_bind(self->hnet, &hsk2, 100));
	EXPECT_EQ(&self->hsk, homa_sock_find(self->hnet, self->hsk.port));
	sock_put(&self->hsk.sock);
	EXPECT_EQ(&hsk2, homa_sock_find(self->hnet, hsk2.port));
	sock_put(&hsk2.sock);
	EXPECT_EQ(NULL, homa_sock_find(self->hnet, hsk2.port + 1));
	unit_sock_destroy(&hsk2);
}
TEST_F(homa_sock, homa_sock_find__same_port_in_different_hnets)
{
	struct homa_sock hsk1, hsk2;
	struct homa_sock *hsk;
	struct homa_net *hnet;

	hnet = mock_hnet(1, &self->homa);
	mock_sock_init(&hsk1, self->hnet, 100);
	mock_sock_init(&hsk2, hnet, 100);

	hsk = homa_sock_find(self->hnet, 100);
	EXPECT_EQ(&hsk1, hsk);
	hsk = homa_sock_find(hnet, 100);
	EXPECT_EQ(&hsk2, hsk);

	sock_put(&hsk1.sock);
	sock_put(&hsk2.sock);
	unit_sock_destroy(&hsk1);
	unit_sock_destroy(&hsk2);
}
TEST_F(homa_sock, homa_sock_find__skip_zero_reference_count)
{
	int saved_refcnt;

	EXPECT_EQ(&self->hsk, homa_sock_find(self->hnet, self->hsk.port));
	sock_put(&self->hsk.sock);

	saved_refcnt = atomic_read(&self->hsk.sock.sk_refcnt.refs);
	atomic_set(&self->hsk.sock.sk_refcnt.refs, 0);
	EXPECT_EQ(NULL, homa_sock_find(self->hnet, self->hsk.port));
	atomic_set(&self->hsk.sock.sk_refcnt.refs, saved_refcnt);
}

TEST_F(homa_sock, homa_sock_find__long_hash_chain)
{
	struct homa_sock hsk2, hsk3, hsk4;

	EXPECT_EQ(0, homa_sock_bind(self->hnet, &self->hsk, 13));
	mock_sock_init(&hsk2, self->hnet, 0);
	EXPECT_EQ(0, homa_sock_bind(self->hnet, &hsk2,
			2*HOMA_SOCKTAB_BUCKETS + 13));
	mock_sock_init(&hsk3, self->hnet, 0);
	EXPECT_EQ(0, homa_sock_bind(self->hnet, &hsk3,
			3*HOMA_SOCKTAB_BUCKETS + 13));
	mock_sock_init(&hsk4, self->hnet, 0);
	EXPECT_EQ(0, homa_sock_bind(self->hnet, &hsk4,
			5*HOMA_SOCKTAB_BUCKETS + 13));

	EXPECT_EQ(&self->hsk, homa_sock_find(self->hnet, 13));
	sock_put(&self->hsk.sock);
	EXPECT_EQ(&hsk2, homa_sock_find(self->hnet, 2*HOMA_SOCKTAB_BUCKETS + 13));
	sock_put(&hsk2.sock);
	EXPECT_EQ(&hsk3, homa_sock_find(self->hnet,
			3*HOMA_SOCKTAB_BUCKETS + 13));
	sock_put(&hsk3.sock);
	EXPECT_EQ(&hsk4, homa_sock_find(self->hnet,
			5*HOMA_SOCKTAB_BUCKETS + 13));
	sock_put(&hsk4.sock);

	unit_sock_destroy(&hsk2);
	unit_sock_destroy(&hsk3);
	unit_sock_destroy(&hsk4);
}

#ifndef __STRIP__ /* See strip.py */
TEST_F(homa_sock, homa_sock_lock_slow)
{
	mock_clock_tick = 100;

	homa_sock_lock(&self->hsk);
	EXPECT_EQ(0, homa_metrics_per_cpu()->socket_lock_misses);
	EXPECT_EQ(0, homa_metrics_per_cpu()->socket_lock_miss_cycles);
	homa_sock_unlock(&self->hsk);

	mock_trylock_errors = 1;
	homa_sock_lock(&self->hsk);
	EXPECT_EQ(1, homa_metrics_per_cpu()->socket_lock_misses);
	EXPECT_EQ(100, homa_metrics_per_cpu()->socket_lock_miss_cycles);
	homa_sock_unlock(&self->hsk);
}
#endif /* See strip.py */

TEST_F(homa_sock, homa_sock_wait_wmem__no_memory_shortage)
{
	EXPECT_EQ(0, -homa_sock_wait_wmem(&self->hsk, 1));
	EXPECT_EQ(1, test_bit(HOMA_SOCK_NOSPACE, &self->hsk.flags));
}
TEST_F(homa_sock, homa_sock_wait_wmem__nonblocking)
{
	self->hsk.sock.sk_sndbuf = 0;
	EXPECT_EQ(EWOULDBLOCK, -homa_sock_wait_wmem(&self->hsk, 1));
	EXPECT_EQ(1, test_bit(HOMA_SOCK_NOSPACE, &self->hsk.flags));
}
TEST_F(homa_sock, homa_sock_wait_wmem__thread_blocks_then_wakes)
{
	self->hsk.sock.sk_sndbuf = 0;
	self->hsk.sock.sk_sndtimeo = 6;
	hook_hsk = &self->hsk;
	hook_count = 5;
	unit_hook_register(schedule_hook);

	EXPECT_EQ(0, -homa_sock_wait_wmem(&self->hsk, 0));
	EXPECT_EQ(1, test_bit(HOMA_SOCK_NOSPACE, &self->hsk.flags));
}
TEST_F(homa_sock, homa_sock_wait_wmem__socket_shutdown)
{
	self->hsk.sock.sk_sndbuf = 0;
	unit_hook_register(shutdown_hook);
	hook_hsk = &self->hsk;

	EXPECT_EQ(ESHUTDOWN, -homa_sock_wait_wmem(&self->hsk, 0));
	EXPECT_EQ(1, self->hsk.shutdown);
}
TEST_F(homa_sock, homa_sock_wait_wmem__interrupted_by_signal)
{
	self->hsk.sock.sk_sndbuf = 0;
	mock_prepare_to_wait_errors = 1;
	mock_signal_pending = 1;

	EXPECT_EQ(EINTR, -homa_sock_wait_wmem(&self->hsk, 0));
}
TEST_F(homa_sock, homa_sock_wait_wmem__thread_blocks_but_times_out)
{
	self->hsk.sock.sk_sndbuf = 0;
	self->hsk.sock.sk_sndtimeo = 4;
	hook_hsk = &self->hsk;
	hook_count = 5;
	unit_hook_register(schedule_hook);

	EXPECT_EQ(EWOULDBLOCK, -homa_sock_wait_wmem(&self->hsk, 0));
}

TEST_F(homa_sock, homa_sock_wakeup_wmem)
{
	self->hsk.sock.sk_sndbuf = 0;
	set_bit(HOMA_SOCK_NOSPACE, &self->hsk.flags);

	/* First call: no memory available. */
	homa_sock_wakeup_wmem(&self->hsk);
	EXPECT_EQ(1, test_bit(HOMA_SOCK_NOSPACE, &self->hsk.flags));

	/* Second call: memory now available. */
	self->hsk.sock.sk_sndbuf = 1000000;
	mock_log_wakeups = 1;
	unit_log_clear();
	homa_sock_wakeup_wmem(&self->hsk);
	EXPECT_EQ(0, test_bit(HOMA_SOCK_NOSPACE, &self->hsk.flags));
	EXPECT_STREQ("wake_up", unit_log_get());
}
