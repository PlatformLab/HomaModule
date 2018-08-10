#include "homa_impl.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

#define n(x) htons(x)
#define N(x) htonl(x)

FIXTURE(homa_socktab) {
	struct homa homa;
	struct homa_sock hsk;
};
FIXTURE_SETUP(homa_socktab)
{
	homa_init(&self->homa);
	mock_sock_init(&self->hsk, &self->homa, 0, 0);
}
FIXTURE_TEARDOWN(homa_socktab)
{
	mock_sock_destroy(&self->hsk, &self->homa.port_map);
	homa_destroy(&self->homa);
	unit_teardown();
}

TEST_F(homa_socktab, homa_port_hash)
{
	EXPECT_EQ(1023, homa_port_hash(0xffff));
	EXPECT_EQ(18, homa_port_hash(0x6012));
	EXPECT_EQ(99, homa_port_hash(99));
}

TEST_F(homa_socktab, homa_sock_init__skip_port_in_use)
{
	struct homa_sock hsk2, hsk3;
	self->homa.next_client_port = 0xffff;
	mock_sock_init(&hsk2, &self->homa, 0, 0);
	mock_sock_init(&hsk3, &self->homa, 0, 0);
	EXPECT_EQ(65535, hsk2.client_port);
	EXPECT_EQ(32769, hsk3.client_port);
	mock_sock_destroy(&hsk2, &self->homa.port_map);
	mock_sock_destroy(&hsk3, &self->homa.port_map);
}

TEST_F(homa_socktab, homa_sock_destroy)
{
	int client2, client3;
	struct homa_sock hsk2, hsk3;
	mock_sock_init(&hsk2, &self->homa, 0, 0);
	EXPECT_EQ(0, homa_sock_bind(&self->homa.port_map, &hsk2, 100));
	client2 = hsk2.client_port;
	mock_sock_init(&hsk3, &self->homa, 0, 0);
	client3 = hsk3.client_port;
	
	EXPECT_EQ(&hsk2, homa_sock_find(&self->homa.port_map, client2));
	EXPECT_EQ(&hsk2, homa_sock_find(&self->homa.port_map, 100));
	EXPECT_EQ(&hsk3, homa_sock_find(&self->homa.port_map, client3));
	
	mock_sock_destroy(&hsk2, &self->homa.port_map);
	
	EXPECT_EQ(NULL, homa_sock_find(&self->homa.port_map, client2));
	EXPECT_EQ(NULL, homa_sock_find(&self->homa.port_map, 100));
	EXPECT_EQ(&hsk3, homa_sock_find(&self->homa.port_map, client3));
	
	mock_sock_destroy(&hsk3, &self->homa.port_map);
	
	EXPECT_EQ(NULL, homa_sock_find(&self->homa.port_map, client2));
	EXPECT_EQ(NULL, homa_sock_find(&self->homa.port_map, 100));
	EXPECT_EQ(NULL, homa_sock_find(&self->homa.port_map, client3));
}

TEST_F(homa_socktab, homa_sock_bind)
{
	struct homa_sock hsk2;
	mock_sock_init(&hsk2, &self->homa, 0, 0);
	EXPECT_EQ(0, homa_sock_bind(&self->homa.port_map, &hsk2, 100));
	
	EXPECT_EQ(EINVAL, -homa_sock_bind(&self->homa.port_map, &self->hsk, 0));
	EXPECT_EQ(EINVAL, -homa_sock_bind(&self->homa.port_map, &self->hsk,
			HOMA_MIN_CLIENT_PORT + 100));
	
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
}

TEST_F(homa_socktab, homa_sock_find__basics)
{
	struct homa_sock hsk2;
	mock_sock_init(&hsk2, &self->homa, 0, 0);
	EXPECT_EQ(0, homa_sock_bind(&self->homa.port_map, &hsk2, 100));
	EXPECT_EQ(&self->hsk, homa_sock_find(&self->homa.port_map,
			self->hsk.client_port));
	EXPECT_EQ(&hsk2, homa_sock_find(&self->homa.port_map,
			hsk2.client_port));
	EXPECT_EQ(&hsk2, homa_sock_find(&self->homa.port_map,
			hsk2.server_port));
	EXPECT_EQ(NULL, homa_sock_find(&self->homa.port_map,
			hsk2.server_port + 1));
	mock_sock_destroy(&hsk2, &self->homa.port_map);
}

TEST_F(homa_socktab, homa_sock_find__long_hash_chain)
{
	struct homa_sock hsk2, hsk3, hsk4;
	EXPECT_EQ(0, homa_sock_bind(&self->homa.port_map, &self->hsk, 13));
	mock_sock_init(&hsk2, &self->homa, 0, 0);
	EXPECT_EQ(0, homa_sock_bind(&self->homa.port_map, &hsk2,
			2*HOMA_SOCKTAB_BUCKETS + 13));
	mock_sock_init(&hsk3, &self->homa, 0, 0);
	EXPECT_EQ(0, homa_sock_bind(&self->homa.port_map, &hsk3,
			3*HOMA_SOCKTAB_BUCKETS + 13));
	mock_sock_init(&hsk4, &self->homa, 0, 0);
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
	
	mock_sock_destroy(&hsk2, &self->homa.port_map);
	mock_sock_destroy(&hsk3, &self->homa.port_map);
	mock_sock_destroy(&hsk4, &self->homa.port_map);
}