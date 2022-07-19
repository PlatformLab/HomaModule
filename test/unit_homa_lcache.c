/* Copyright (c) 20221, Stanford University
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
#include "homa_lcache.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

FIXTURE(homa_lcache) {
	struct homa_lcache cache;
	struct homa homa;
	struct homa_sock hsk;
	struct homa_rpc *crpc;
	struct homa_rpc *srpc;
};
FIXTURE_SETUP(homa_lcache)
{
	homa_lcache_init(&self->cache);
	homa_init(&self->homa);
	mock_sock_init(&self->hsk, &self->homa, 0);
	self->crpc = unit_client_rpc(&self->hsk,
			RPC_READY, unit_get_in_addr("196.168.0.1"),
			unit_get_in_addr("1.2.3.4"), 99, 1234, 1000, 1000);
	self->srpc = unit_server_rpc(&self->hsk, RPC_READY,
			unit_get_in_addr("196.168.0.1"),
			unit_get_in_addr("1.2.3.4"), 40000,
			1235, 1000, 1000);
}
FIXTURE_TEARDOWN(homa_lcache)
{
	homa_destroy(&self->homa);
	unit_teardown();
}

TEST_F(homa_lcache, constructor)
{
	EXPECT_TRUE(self->cache.rpc == NULL);
}

TEST_F(homa_lcache, homa_lcache_save__empty)
{
	homa_lcache_save(&self->cache, self->crpc);
	EXPECT_EQ(self->crpc, self->cache.rpc);
}
TEST_F(homa_lcache, homa_lcache_save__full)
{
	homa_rpc_lock(self->crpc);
	homa_lcache_save(&self->cache, self->crpc);
	homa_rpc_lock(self->srpc);
	homa_lcache_save(&self->cache, self->srpc);
	EXPECT_EQ(self->srpc, self->cache.rpc);
	homa_lcache_release(&self->cache);
}

TEST_F(homa_lcache, homa_lcache_release)
{
	homa_lcache_release(&self->cache);
	homa_rpc_lock(self->crpc);
	homa_lcache_save(&self->cache, self->crpc);
	homa_lcache_release(&self->cache);
	EXPECT_TRUE(self->cache.rpc == NULL);
}

TEST_F(homa_lcache, homa_lcache_get)
{
	__be32 client_addr = unit_get_in_addr("196.168.0.1");
	EXPECT_TRUE(homa_lcache_get(&self->cache, 1235, client_addr,
			40000) == NULL);
	homa_lcache_save(&self->cache, self->srpc);
	EXPECT_EQ(self->srpc, homa_lcache_get(&self->cache, 1235,
			client_addr, 40000));
	EXPECT_TRUE(homa_lcache_get(&self->cache, 1237, client_addr,
			40000) == NULL);
	EXPECT_TRUE(homa_lcache_get(&self->cache, 1235, client_addr+1,
			40000) == NULL);
	EXPECT_TRUE(homa_lcache_get(&self->cache, 1235, client_addr,
			40001) == NULL);
}