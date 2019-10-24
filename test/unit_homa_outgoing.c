/* Copyright (c) 2019, Stanford University
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
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

FIXTURE(homa_outgoing) {
	__be32 client_ip;
	int client_port;
	__be32 server_ip;
	int server_port;
	__u64 rpcid;
	struct homa homa;
	struct homa_sock hsk;
	struct sockaddr_in server_addr;
};
FIXTURE_SETUP(homa_outgoing)
{
	self->client_ip = unit_get_in_addr("196.168.0.1");
	self->client_port = 40000;
	self->server_ip = unit_get_in_addr("1.2.3.4");
	self->server_port = 99;
	self->rpcid = 12345;
	homa_init(&self->homa);
	mock_cycles = 10000;
	atomic_long_set(&self->homa.link_idle_time, 10000);
	self->homa.cycles_per_kbyte = 1000;
	self->homa.flags |= HOMA_FLAG_DONT_THROTTLE;
	mock_sock_init(&self->hsk, &self->homa, self->client_port,
			self->server_port);
	self->server_addr.sin_family = AF_INET;
	self->server_addr.sin_addr.s_addr = self->server_ip;
	self->server_addr.sin_port = htons(self->server_port);
	unit_log_clear();
}
FIXTURE_TEARDOWN(homa_outgoing)
{
	homa_destroy(&self->homa);
	unit_teardown();
}

TEST_F(homa_outgoing, homa_message_out_init__basics)
{
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 3000, NULL);
	EXPECT_NE(NULL, crpc);
	EXPECT_EQ(3000, crpc->msgout.granted);
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_STREQ("csum_and_copy_from_iter_full copied 1400 bytes; "
		"csum_and_copy_from_iter_full copied 1400 bytes; "
		"csum_and_copy_from_iter_full copied 200 bytes", unit_log_get());
	unit_log_clear();
	unit_log_message_out_packets(&crpc->msgout, 1);
	EXPECT_STREQ("DATA from 0.0.0.0:40000, dport 99, id 1, "
			"message_length 3000, offset 0, data_length 1400, "
			"incoming 10000, cutoff_version 0; "
		     "DATA from 0.0.0.0:40000, dport 99, id 1, "
			"message_length 3000, offset 1400, data_length 1400, "
			"incoming 10000, cutoff_version 0; "
		     "DATA from 0.0.0.0:40000, dport 99, id 1, "
			"message_length 3000, offset 2800, data_length 200, "
			"incoming 10000, cutoff_version 0",
		     unit_log_get());
	EXPECT_EQ(3, crpc->num_skbuffs);
}
TEST_F(homa_outgoing, homa_message_out_init__message_too_long)
{
	mock_alloc_skb_errors = 2;
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 2000000, NULL);
	EXPECT_TRUE(IS_ERR(crpc));
	EXPECT_EQ(EINVAL, -PTR_ERR(crpc));
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
}
TEST_F(homa_outgoing, homa_message_out_init__max_gso_size_limit)
{
	mock_net_device.gso_max_size = 10000;
	self->homa.max_gso_size = 3000;
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 5000, NULL);
	EXPECT_NE(NULL, crpc);
	unit_log_clear();
	unit_log_message_out_packets(&crpc->msgout, 0);
	EXPECT_STREQ("DATA P1 1400@0 1400@1400; "
			"DATA P1 1400@2800 800@4200",
			unit_log_get());
}
TEST_F(homa_outgoing, homa_message_out_init__cant_alloc_small_skb)
{
	mock_alloc_skb_errors = 1;
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 500, NULL);
	EXPECT_TRUE(IS_ERR(crpc));
	EXPECT_EQ(ENOMEM, -PTR_ERR(crpc));
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
}
TEST_F(homa_outgoing, homa_message_out_init__cant_alloc_large_skb)
{
	mock_alloc_skb_errors = 1;
	mock_net_device.gso_max_size = 5000;
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 5000, NULL);
	EXPECT_TRUE(IS_ERR(crpc));
	EXPECT_EQ(ENOMEM, -PTR_ERR(crpc));
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
}
TEST_F(homa_outgoing, homa_message_out_init__cant_copy_data)
{
	mock_copy_data_errors = 2;
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 3000, NULL);
	EXPECT_TRUE(IS_ERR(crpc));
	EXPECT_EQ(EFAULT, -PTR_ERR(crpc));
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
}
TEST_F(homa_outgoing, homa_message_out_init__multiple_segs_per_skbuff)
{
	mock_net_device.gso_max_size = 5000;
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 10000, NULL);
	EXPECT_NE(NULL, crpc);
	unit_log_clear();
	unit_log_message_out_packets(&crpc->msgout, 0);
	EXPECT_STREQ("DATA P1 1400@0 1400@1400 1400@2800; "
			"DATA P1 1400@4200 1400@5600 1400@7000; "
			"DATA P1 1400@8400 200@9800",
			unit_log_get());
	EXPECT_EQ(3, crpc->num_skbuffs);
}
TEST_F(homa_outgoing, homa_message_out_init__use_small_extra_space)
{
	mock_net_device.gso_max_size = 1800;
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 1600, NULL);
	EXPECT_NE(NULL, crpc);
	unit_log_clear();
	unit_log_message_out_packets(&crpc->msgout, 0);
	EXPECT_STREQ("DATA P1 1400@0 200@1400",
			unit_log_get());
	EXPECT_EQ(1, crpc->num_skbuffs);
}
TEST_F(homa_outgoing, homa_message_out_init__set_incoming)
{
	struct data_header *h;
	mock_net_device.gso_max_size = 6000;
	self->homa.max_gso_size = 6000;
	self->homa.rtt_bytes = 1000;
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 10000, NULL);
	EXPECT_NE(NULL, crpc);
	unit_log_clear();
	unit_log_message_out_packets(&crpc->msgout, 0);
	EXPECT_STREQ("DATA P1 1400@0 1400@1400 1400@2800 1400@4200; "
			"DATA P1 1400@5600 1400@7000 1400@8400 200@9800",
			unit_log_get());
	h = (struct data_header *) skb_transport_header(crpc->msgout.packets);
	EXPECT_EQ(5600, ntohl(h->incoming));
	h = (struct data_header *) skb_transport_header(
			*homa_next_skb(crpc->msgout.packets));
	EXPECT_EQ(10000, ntohl(h->incoming));
}
TEST_F(homa_outgoing, homa_message_out_init__expand_last_segment)
{
	mock_net_device.gso_max_size = 5000;
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 1402, NULL);
	EXPECT_NE(NULL, crpc);
	unit_log_clear();
	unit_log_message_out_packets(&crpc->msgout, 0);
	EXPECT_STREQ("DATA P1 1400@0 2@1400", unit_log_get());
	EXPECT_EQ(1416, crpc->msgout.packets->len - sizeof32(struct data_header)
			- sizeof32(struct data_segment));
}

TEST_F(homa_outgoing, homa_message_out_reset__basics)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk, RPC_OUTGOING,
		self->client_ip, self->server_ip, self->server_port,
		1111, 3000, 100);
	EXPECT_NE(NULL, crpc);
	homa_xmit_data(crpc, false);
	EXPECT_EQ(NULL, crpc->msgout.next_packet);
	crpc->msgout.granted = 0;
	homa_message_out_reset(crpc);
	EXPECT_EQ(3000, crpc->msgout.granted);
	EXPECT_EQ(crpc->msgout.packets, crpc->msgout.next_packet);
	unit_log_clear();
	unit_log_message_out_packets(&crpc->msgout, 0);
	EXPECT_STREQ("DATA P1 1400@0; DATA P1 1400@1400; DATA P1 200@2800",
			unit_log_get());
}
TEST_F(homa_outgoing, homa_message_out_reset__cant_allocate_skb)
{
	int err;
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk, RPC_OUTGOING,
		self->client_ip, self->server_ip, self->server_port,
		1111, 3000, 100);
	EXPECT_NE(NULL, crpc);
	mock_alloc_skb_errors = 2;
	err = homa_message_out_reset(crpc);
	EXPECT_EQ(ENOMEM, -err);
	unit_log_clear();
	unit_log_message_out_packets(&crpc->msgout, 0);
	EXPECT_STREQ("DATA P1 1400@0; DATA P1 200@2800", unit_log_get());
}

TEST_F(homa_outgoing, homa_set_priority)
{
	struct sk_buff *skb = alloc_skb(1000, GFP_KERNEL);
	homa_set_priority(skb, 0);
	EXPECT_EQ(1, (skb->vlan_tci & VLAN_PRIO_MASK) >> VLAN_PRIO_SHIFT);
	
	homa_set_priority(skb, 1);
	EXPECT_EQ(0, (skb->vlan_tci & VLAN_PRIO_MASK) >> VLAN_PRIO_SHIFT);
	
	homa_set_priority(skb, 7);
	EXPECT_EQ(7, (skb->vlan_tci & VLAN_PRIO_MASK) >> VLAN_PRIO_SHIFT);
	kfree_skb(skb);
}

TEST_F(homa_outgoing, homa_xmit_control__server_request)
{
	struct homa_rpc *srpc;
	struct grant_header h;
	
	srpc = unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
		self->server_ip, self->client_port, 1111, 10000, 10000);
	EXPECT_NE(NULL, srpc);
	
	h.offset = htonl(12345);
	h.priority = 4;
	mock_xmit_log_verbose = 1;
	EXPECT_EQ(0, homa_xmit_control(GRANT, &h, sizeof(h), srpc));
	EXPECT_STREQ("xmit GRANT from 0.0.0.0:99, dport 40000, id 1111, "
			"prio 7, offset 12345, grant_prio 4",
			unit_log_get());
}
TEST_F(homa_outgoing, homa_xmit_control__client_response)
{
	struct homa_rpc *crpc;
	struct grant_header h;
	
	crpc = unit_client_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
		self->server_ip, self->server_port, 1111, 100, 10000);
	EXPECT_NE(NULL, crpc);
	unit_log_clear();
	
	h.offset = htonl(12345);
	h.priority = 4;
	mock_xmit_log_verbose = 1;
	EXPECT_EQ(0, homa_xmit_control(GRANT, &h, sizeof(h), crpc));
	EXPECT_STREQ("xmit GRANT from 0.0.0.0:40000, dport 99, id 1111, "
			"prio 7, offset 12345, grant_prio 4",
			unit_log_get());
}

TEST_F(homa_outgoing, __homa_xmit_control__cant_alloc_skb)
{
	struct homa_rpc *srpc;
	struct grant_header h;
	
	srpc = unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
		self->server_ip, self->client_port, 1111, 10000, 10000);
	EXPECT_NE(NULL, srpc);
	
	h.common.type = GRANT;
	h.offset = htonl(12345);
	h.priority = 4;
	mock_xmit_log_verbose = 1;
	mock_alloc_skb_errors = 1;
	EXPECT_EQ(ENOBUFS, -__homa_xmit_control(&h, sizeof(h), srpc->peer,
			&self->hsk));
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_outgoing, __homa_xmit_control__pad_packet)
{
	struct homa_rpc *srpc;
	struct grant_header h;
	
	srpc = unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
		self->server_ip, self->client_port, 1111, 10000, 10000);
	EXPECT_NE(NULL, srpc);
	
	h.offset = htonl(12345);
	h.priority = 4;
	mock_xmit_log_verbose = 1;
	EXPECT_EQ(0, homa_xmit_control(GRANT, &h, sizeof(h), srpc));
	EXPECT_SUBSTR("offset 12345, grant_prio 4", unit_log_get());
}
TEST_F(homa_outgoing, __homa_xmit_control__ip_queue_xmit_error)
{
	struct homa_rpc *srpc;
	struct grant_header h;
	
	srpc = unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
		self->server_ip, self->client_port, 1111, 10000, 10000);
	EXPECT_NE(NULL, srpc);
	
	h.offset = htonl(12345);
	h.priority = 4;
	mock_xmit_log_verbose = 1;
	mock_ip_queue_xmit_errors = 1;
	EXPECT_EQ(ENETDOWN, -homa_xmit_control(GRANT, &h, sizeof(h), srpc));
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(1, unit_get_metrics()->control_xmit_errors);
}

TEST_F(homa_outgoing, homa_xmit_data__basics)
{
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 6000, NULL);
	EXPECT_NE(NULL, crpc);
	crpc->msgout.sched_priority = 2;
	crpc->msgout.unscheduled = 2000;
	crpc->msgout.granted = 5000;
	homa_peer_set_cutoffs(crpc->peer, INT_MAX, 0, 0, 0, 0, INT_MAX,
			7000, 0);
	unit_log_clear();
	homa_xmit_data(crpc, false);
	EXPECT_STREQ("xmit DATA P6 1400@0; "
			"xmit DATA P6 1400@1400; "
			"xmit DATA P2 1400@2800; "
			"xmit DATA P2 1400@4200", unit_log_get());
	EXPECT_EQ(5600, homa_data_offset(crpc->msgout.next_packet));
}
TEST_F(homa_outgoing, homa_xmit_data__below_throttle_min)
{
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 200, NULL);
	EXPECT_NE(NULL, crpc);
	unit_log_clear();
	atomic_long_set(&self->homa.link_idle_time, 11000);
	self->homa.max_nic_queue_cycles = 500;
	self->homa.flags &= ~HOMA_FLAG_DONT_THROTTLE;
	homa_xmit_data(crpc, false);
	EXPECT_STREQ("xmit DATA P6 200@0", unit_log_get());
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_outgoing, homa_xmit_data__throttle)
{
	struct homa_rpc *crpc1 = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 6000, NULL);
	struct homa_rpc *crpc2 = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 5000, NULL);
	EXPECT_NE(NULL, crpc1);
	EXPECT_NE(NULL, crpc2);
	unit_log_clear();
	atomic_long_set(&self->homa.link_idle_time, 11000);
	self->homa.max_nic_queue_cycles = 3000;
	self->homa.flags &= ~HOMA_FLAG_DONT_THROTTLE;
	
	/* The first RPC throttles because the NIC queueu is too full. */
	homa_xmit_data(crpc1, false);
	EXPECT_STREQ("xmit DATA P6 1400@0; "
			"xmit DATA P6 1400@1400; "
			"wake_up_process", unit_log_get());
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("request 1, next_offset 2800", unit_log_get());
	
	/* The second RPC throttles because the throttle list isn't empty. */
	unit_log_clear();
	self->homa.max_nic_queue_cycles = 20000;
	homa_xmit_data(crpc2, false);
	EXPECT_STREQ("wake_up_process", unit_log_get());
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("request 1, next_offset 2800; request 2, next_offset 0",
			unit_log_get());
}
TEST_F(homa_outgoing, homa_xmit_data__pacer)
{
	struct homa_rpc *crpc1 = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 6000, NULL);
	struct homa_rpc *crpc2 = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 5000, NULL);
	EXPECT_NE(NULL, crpc1);
	EXPECT_NE(NULL, crpc2);
	
	/* First, get an RPC on the throttled list. */
	atomic_long_set(&self->homa.link_idle_time, 11000);
	self->homa.max_nic_queue_cycles = 3000;
	self->homa.flags &= ~HOMA_FLAG_DONT_THROTTLE;
	homa_xmit_data(crpc1, false);
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("request 1, next_offset 2800", unit_log_get());
	
	/* Now the test RPC. */
	unit_log_clear();
	homa_xmit_data(crpc2, true);
	EXPECT_STREQ("", unit_log_get());
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("request 1, next_offset 2800", unit_log_get());
}

TEST_F(homa_outgoing, __homa_xmit_data__update_cutoff_version)
{
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 1000, NULL);
	EXPECT_NE(NULL, crpc);
	crpc->peer->cutoff_version = htons(123);
	mock_xmit_log_verbose = 1;
	unit_log_clear();
	skb_get(crpc->msgout.packets);
	__homa_xmit_data(crpc->msgout.packets, crpc, 4);
	EXPECT_SUBSTR("cutoff_version 123", unit_log_get());
}
TEST_F(homa_outgoing, __homa_xmit_data__fill_dst)
{
	int old_refcount;
	struct dst_entry *dst;
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 1000, NULL);
	EXPECT_NE(NULL, crpc);
	unit_log_clear();
	dst = crpc->peer->dst;
	old_refcount = dst->__refcnt.counter;
	
	skb_get(crpc->msgout.packets);
	__homa_xmit_data(crpc->msgout.packets, crpc, 6);
	EXPECT_STREQ("xmit DATA P6 1000@0", unit_log_get());
	EXPECT_EQ(dst, skb_dst(crpc->msgout.packets));
	EXPECT_EQ(old_refcount+1, dst->__refcnt.counter);
}
TEST_F(homa_outgoing, __homa_xmit_data__transmit_error)
{
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 1000, NULL);
	EXPECT_NE(NULL, crpc);
	unit_log_clear();
	mock_ip_queue_xmit_errors = 1;
	skb_get(crpc->msgout.packets);
	__homa_xmit_data(crpc->msgout.packets, crpc, 5);
	EXPECT_EQ(1, unit_get_metrics()->data_xmit_errors);
}

TEST_F(homa_outgoing, homa_resend_data)
{
	mock_net_device.gso_max_size = 5000;
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 16000, NULL);
	EXPECT_NE(NULL, crpc);
	unit_log_clear();
	mock_xmit_log_verbose = 1;
	homa_resend_data(crpc, 7000, 10000, 2);
	EXPECT_STREQ("xmit DATA from 0.0.0.0:40000, dport 99, id 1, prio 2, "
			"message_length 16000, offset 7000, data_length 1400, "
			"incoming 10000, cutoff_version 0, RETRANSMIT; "
			"xmit DATA from 0.0.0.0:40000, dport 99, id 1, prio 2, "
			"message_length 16000, offset 8400, data_length 1400, "
			"incoming 10000, cutoff_version 0, RETRANSMIT; "
			"xmit DATA from 0.0.0.0:40000, dport 99, id 1, prio 2, "
			"message_length 16000, offset 9800, data_length 1400, "
			"incoming 11200, cutoff_version 0, RETRANSMIT",
			unit_log_get());
	
	unit_log_clear();
	mock_xmit_log_verbose = 0;
	homa_resend_data(crpc, 2800, 4200, 3);
	EXPECT_STREQ("xmit DATA retrans P3 1400@2800", unit_log_get());
	
	unit_log_clear();
	mock_xmit_log_verbose = 0;
	homa_resend_data(crpc, 4199, 4201, 7);
	EXPECT_STREQ("xmit DATA retrans P7 1400@2800; "
			"xmit DATA retrans P7 1400@4200", unit_log_get());
	
	unit_log_clear();
	mock_xmit_log_verbose = 0;
	homa_resend_data(crpc, 16000, 17000, 7);
	EXPECT_STREQ("", unit_log_get());
}

TEST_F(homa_outgoing, homa_outgoing_sysctl_changed)
{
	self->homa.link_mbps = 10000;
	homa_outgoing_sysctl_changed(&self->homa);
	EXPECT_EQ(840, self->homa.cycles_per_kbyte);
	
	self->homa.link_mbps = 1000;
	homa_outgoing_sysctl_changed(&self->homa);
	EXPECT_EQ(8400, self->homa.cycles_per_kbyte);
	
	self->homa.link_mbps = 40000;
	homa_outgoing_sysctl_changed(&self->homa);
	EXPECT_EQ(210, self->homa.cycles_per_kbyte);
	
	self->homa.max_nic_queue_ns = 200;
	cpu_khz = 2000000;
	homa_outgoing_sysctl_changed(&self->homa);
	EXPECT_EQ(400, self->homa.max_nic_queue_cycles);
}

TEST_F(homa_outgoing, homa_check_nic_queue__basics)
{
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 500 - sizeof(struct data_header)
			- HOMA_IPV4_HEADER_LENGTH - HOMA_VLAN_HEADER
			- HOMA_ETH_OVERHEAD, NULL);
	EXPECT_NE(NULL, crpc);
	unit_log_clear();
	atomic_long_set(&self->homa.link_idle_time, 9000);
	mock_cycles = 8000;
	self->homa.max_nic_queue_cycles = 1000;
	self->homa.flags &= ~HOMA_FLAG_DONT_THROTTLE;
	EXPECT_EQ(1, homa_check_nic_queue(&self->homa, crpc->msgout.packets,
			false));
	EXPECT_EQ(9500, atomic_long_read(&self->homa.link_idle_time));
}
TEST_F(homa_outgoing, homa_check_nic_queue__multiple_packets_gso)
{
	mock_mtu = 500 - sizeof(struct data_header)
			- HOMA_IPV4_HEADER_LENGTH - HOMA_VLAN_HEADER
			- HOMA_ETH_OVERHEAD;
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 1200 - 3 *(sizeof(struct data_header)
			+ HOMA_IPV4_HEADER_LENGTH + HOMA_VLAN_HEADER
			+ HOMA_ETH_OVERHEAD), NULL);
	EXPECT_NE(NULL, crpc);
	unit_log_clear();
	atomic_long_set(&self->homa.link_idle_time, 9000);
	self->homa.max_nic_queue_cycles = 100000;
	self->homa.flags &= ~HOMA_FLAG_DONT_THROTTLE;
	mock_cycles = 0;
	EXPECT_EQ(1, homa_check_nic_queue(&self->homa, crpc->msgout.packets,
			false));
	EXPECT_EQ(10200, atomic_long_read(&self->homa.link_idle_time));
}
TEST_F(homa_outgoing, homa_check_nic_queue__queue_full)
{
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 500 - sizeof(struct data_header)
			- HOMA_IPV4_HEADER_LENGTH - HOMA_VLAN_HEADER
			- HOMA_ETH_OVERHEAD, NULL);
	EXPECT_NE(NULL, crpc);
	unit_log_clear();
	atomic_long_set(&self->homa.link_idle_time, 9000);
	mock_cycles = 7999;
	self->homa.max_nic_queue_cycles = 1000;
	self->homa.flags &= ~HOMA_FLAG_DONT_THROTTLE;
	EXPECT_EQ(0, homa_check_nic_queue(&self->homa, crpc->msgout.packets,
			false));
	EXPECT_EQ(9000, atomic_long_read(&self->homa.link_idle_time));
}
TEST_F(homa_outgoing, homa_check_nic_queue__queue_full_but_force)
{
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 500 - sizeof(struct data_header)
			- HOMA_IPV4_HEADER_LENGTH - HOMA_VLAN_HEADER
			- HOMA_ETH_OVERHEAD, NULL);
	EXPECT_NE(NULL, crpc);
	unit_log_clear();
	atomic_long_set(&self->homa.link_idle_time, 9000);
	mock_cycles = 7999;
	self->homa.max_nic_queue_cycles = 1000;
	self->homa.flags &= ~HOMA_FLAG_DONT_THROTTLE;
	EXPECT_EQ(1, homa_check_nic_queue(&self->homa, crpc->msgout.packets,
			true));
	EXPECT_EQ(9500, atomic_long_read(&self->homa.link_idle_time));
}
TEST_F(homa_outgoing, homa_check_nic_queue__queue_empty)
{
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 500 - sizeof(struct data_header)
			- HOMA_IPV4_HEADER_LENGTH - HOMA_VLAN_HEADER
			- HOMA_ETH_OVERHEAD, NULL);
	EXPECT_NE(NULL, crpc);
	unit_log_clear();
	atomic_long_set(&self->homa.link_idle_time, 9000);
	mock_cycles = 10000;
	self->homa.max_nic_queue_cycles = 1000;
	self->homa.flags &= ~HOMA_FLAG_DONT_THROTTLE;
	EXPECT_EQ(1, homa_check_nic_queue(&self->homa, crpc->msgout.packets,
			true));
	EXPECT_EQ(10500, atomic_long_read(&self->homa.link_idle_time));
}

/* Don't know how to unit test homa_pacer_main... */

TEST_F(homa_outgoing, homa_pacer_xmit__basics)
{
	struct homa_rpc *crpc1 = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 5000, NULL);
	struct homa_rpc *crpc2 = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 10000, NULL);
	struct homa_rpc *crpc3 = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 15000, NULL);
	EXPECT_NE(NULL, crpc1);
	EXPECT_NE(NULL, crpc2);
	EXPECT_NE(NULL, crpc3);
	homa_add_to_throttled(crpc1);
	homa_add_to_throttled(crpc2);
	homa_add_to_throttled(crpc3);
	self->homa.max_nic_queue_cycles = 2000;
	self->homa.flags &= ~HOMA_FLAG_DONT_THROTTLE;
	unit_log_clear();
	homa_pacer_xmit(&self->homa, 0);
	EXPECT_STREQ("xmit DATA P6 1400@0; xmit DATA P6 1400@1400",
		unit_log_get());
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("request 1, next_offset 2800; "
		"request 2, next_offset 0; "
		"request 3, next_offset 0", unit_log_get());
}
TEST_F(homa_outgoing, homa_pacer_xmit__pacer_busy)
{
	struct homa_rpc *crpc1 = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 10000, NULL);
	EXPECT_NE(NULL, crpc1);
	homa_add_to_throttled(crpc1);
	self->homa.max_nic_queue_cycles = 2000;
	self->homa.flags &= ~HOMA_FLAG_DONT_THROTTLE;
	atomic_set(&self->homa.pacer_active, 1);
	unit_log_clear();
	homa_pacer_xmit(&self->homa, 0);
	EXPECT_STREQ("", unit_log_get());
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("request 1, next_offset 0", unit_log_get());
}
TEST_F(homa_outgoing, homa_pacer_xmit__nic_queue_full)
{
	struct homa_rpc *crpc1 = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 10000, NULL);
	EXPECT_NE(NULL, crpc1);
	homa_add_to_throttled(crpc1);
	self->homa.max_nic_queue_cycles = 2000;
	mock_cycles = 10000;
	atomic_long_set(&self->homa.link_idle_time, 12010);
	self->homa.flags &= ~HOMA_FLAG_DONT_THROTTLE;
	unit_log_clear();
	homa_pacer_xmit(&self->homa, 0);
	EXPECT_STREQ("", unit_log_get());
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("request 1, next_offset 0", unit_log_get());
}
TEST_F(homa_outgoing, homa_pacer_xmit__queue_empty)
{
	self->homa.max_nic_queue_cycles = 2000;
	self->homa.flags &= ~HOMA_FLAG_DONT_THROTTLE;
	unit_log_clear();
	homa_pacer_xmit(&self->homa, 0);
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_outgoing, homa_pacer_xmit__spin_lock_unavailable)
{
	struct homa_rpc *crpc1 = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 10000, NULL);
	EXPECT_NE(NULL, crpc1);
	lock_sock((struct sock *) crpc1->hsk);
	homa_add_to_throttled(crpc1);
	self->homa.flags &= ~HOMA_FLAG_DONT_THROTTLE;
	unit_log_clear();
	mock_spin_lock_held = 1;
	homa_pacer_xmit(&self->homa, 0);
	EXPECT_STREQ("socket owned", unit_log_get());
	release_sock((struct sock *) crpc1->hsk);
}
TEST_F(homa_outgoing, homa_pacer_xmit__socket_locked)
{
	struct homa_rpc *crpc1 = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 10000, NULL);
	EXPECT_NE(NULL, crpc1);
	lock_sock((struct sock *) crpc1->hsk);
	homa_add_to_throttled(crpc1);
	self->homa.flags &= ~HOMA_FLAG_DONT_THROTTLE;
	unit_log_clear();
	homa_pacer_xmit(&self->homa, 0);
	EXPECT_STREQ("socket owned", unit_log_get());
	release_sock((struct sock *) crpc1->hsk);
}
TEST_F(homa_outgoing, homa_pacer_xmit__remove_from_queue)
{
	struct homa_rpc *crpc1 = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 1000, NULL);
	struct homa_rpc *crpc2 = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 10000, NULL);
	EXPECT_NE(NULL, crpc1);
	EXPECT_NE(NULL, crpc2);
	homa_add_to_throttled(crpc1);
	homa_add_to_throttled(crpc2);
	self->homa.max_nic_queue_cycles = 2000;
	self->homa.flags &= ~HOMA_FLAG_DONT_THROTTLE;
	unit_log_clear();
	homa_pacer_xmit(&self->homa, 0);
	EXPECT_STREQ("xmit DATA P6 1000@0; xmit DATA P6 1400@0",
			unit_log_get());
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("request 2, next_offset 1400", unit_log_get());
	EXPECT_TRUE(list_empty(&crpc1->throttled_links));
}
TEST_F(homa_outgoing, homa_pacer_xmit__delete_rpc)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_OUTGOING,
			self->client_ip, self->server_ip, self->client_port,
			self->rpcid, 100, 1000);
	EXPECT_NE(NULL, srpc);
	EXPECT_FALSE(list_empty(&self->hsk.active_rpcs));
	homa_add_to_throttled(srpc);
	self->homa.max_nic_queue_cycles = 2000;
	self->homa.flags &= ~HOMA_FLAG_DONT_THROTTLE;
	unit_log_clear();
	homa_pacer_xmit(&self->homa, 0);
	EXPECT_STREQ("xmit DATA P6 1000@0; homa_remove_from_grantable invoked",
			unit_log_get());
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_TRUE(list_empty(&self->hsk.active_rpcs));
}

/* Don't know how to unit test homa_pacer_stop... */

TEST_F(homa_outgoing, homa_add_to_throttled)
{
	struct homa_rpc *crpc1 = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 10000, NULL);
	struct homa_rpc *crpc2 = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 5000, NULL);
	struct homa_rpc *crpc3 = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 15000, NULL);
	struct homa_rpc *crpc4 = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 12000, NULL);
	struct homa_rpc *crpc5 = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 10000, NULL);
	EXPECT_NE(NULL, crpc1);
	EXPECT_NE(NULL, crpc5);
	
	/* Basics: add one RPC. */
	homa_add_to_throttled(crpc1);
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("request 1, next_offset 0", unit_log_get());
	
	/* Check priority ordering. */
	homa_add_to_throttled(crpc2);
	homa_add_to_throttled(crpc3);
	homa_add_to_throttled(crpc4);
	homa_add_to_throttled(crpc5);
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("request 2, next_offset 0; "
		"request 1, next_offset 0; "
		"request 5, next_offset 0; "
		"request 4, next_offset 0; "
		"request 3, next_offset 0", unit_log_get());
	
	/* Don't reinsert if already present. */
	homa_add_to_throttled(crpc1);
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("request 2, next_offset 0; "
		"request 1, next_offset 0; "
		"request 5, next_offset 0; "
		"request 4, next_offset 0; "
		"request 3, next_offset 0", unit_log_get());
}