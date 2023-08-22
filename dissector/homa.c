/* homa.c
 * Wireshark HOMA Plugin
 *
 * Copyright 2023 Missing Link Electronics Inc,
 * Björn Petersen <bjoern.petersen@missinglinkelectronics.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <epan/packet.h>
#include <ws_version.h>

#ifndef VERSION
#define VERSION "0.0.1"
#endif

WS_DLL_PUBLIC_DEF const gchar plugin_version[] = VERSION;
WS_DLL_PUBLIC_DEF const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = WIRESHARK_VERSION_MINOR;

#define HOMA_PROTO 0xFD

#define HOMA_HEADER_TYPE_OFFSET 13
#define HOMA_DATA_PACKET 0x10
#define HOMA_GRANT_PACKET 0x11
#define HOMA_RESEND_PACKET 0x12
#define HOMA_UNKNOWN_PACKET 0x13
#define HOMA_BUSY_PACKET 0x14
#define HOMA_CUTOFFS_PACKET 0x15
#define HOMA_FREEZE_PACKET 0x16
#define HOMA_NEED_ACK_PACKET 0x17
#define HOMA_ACK_PACKET 0x18

#define COMMON_HEADER_LENGTH 28
#define HOMA_ACK_LENGTH 12
#define DATA_SEGMENT_LENGTH (8 + HOMA_ACK_LENGTH)
#define DATA_HEADER_LENGTH (12 + DATA_SEGMENT_LENGTH)
#define RESEND_HEADER_LENGTH 9
#define GRANT_HEADER_LENGTH 5
#define CUTOFFS_HEADER_LENGTH 34
#define ACK_HEADER_LENGTH 62

static int proto_homa = -1;

static int hf_homa_common_sport = -1;
static int hf_homa_common_dport = -1;
static int hf_homa_common_doff = -1;
static int hf_homa_common_type = -1;
static int hf_homa_common_sender_id = -1;
static int hf_homa_data_message_length = -1;
static int hf_homa_data_incoming = -1;
static int hf_homa_data_cutoff_version = -1;
static int hf_homa_data_retransmit = -1;
static int hf_homa_data_offset = -1;
static int hf_homa_data_segment_length = -1;
static int hf_homa_ack_client_id = -1;
static int hf_homa_ack_client_port = -1;
static int hf_homa_ack_server_port = -1;
static int hf_homa_grant_offset = -1;
static int hf_homa_grant_priority = -1;
static int hf_homa_resend_offset = -1;
static int hf_homa_resend_length = -1;
static int hf_homa_resend_priority = -1;
static int hf_homa_ack_num_acks = -1;
static int hf_homa_cutoff_unsched_cutoffs = -1;
static int hf_homa_cutoff_version = -1;

static int ett_homa_common = -1;

static int dissect_homa(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_,
			void *data _U_)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Homa");
	/* Clear the info column */
	col_clear(pinfo->cinfo, COL_INFO);
	gint header_length = COMMON_HEADER_LENGTH;
	gint homa_packet_type = tvb_get_guint8(tvb, HOMA_HEADER_TYPE_OFFSET);
	switch (homa_packet_type) { // Calculate Length of Header depending on the header type
	case HOMA_DATA_PACKET:
		header_length += DATA_HEADER_LENGTH;
		break;
	case HOMA_RESEND_PACKET:
		header_length += RESEND_HEADER_LENGTH;
		break;
	case HOMA_GRANT_PACKET:
		header_length += GRANT_HEADER_LENGTH;
		break;
	case HOMA_ACK_PACKET:
		header_length += ACK_HEADER_LENGTH;
		break;
	case HOMA_CUTOFFS_PACKET:
		header_length += CUTOFFS_HEADER_LENGTH;
		break;
	}
	proto_item *ti = proto_tree_add_item(tree, proto_homa, tvb, 0,
					     header_length, ENC_NA);
	proto_tree *homa_tree = proto_item_add_subtree(ti, ett_homa_common);
	proto_tree *homa_tree_common = NULL;
	switch (homa_packet_type) { // Select tree for information
	case HOMA_DATA_PACKET:
	case HOMA_GRANT_PACKET:
	case HOMA_CUTOFFS_PACKET:
	case HOMA_ACK_PACKET:
	case HOMA_RESEND_PACKET:
		homa_tree_common = proto_tree_add_subtree(homa_tree, tvb, 0,
							  COMMON_HEADER_LENGTH,
							  0, &ti,
							  "Common Header");
		break;
	case HOMA_NEED_ACK_PACKET:
		col_set_str(pinfo->cinfo, COL_INFO, "Need ACK Packet");
		homa_tree_common = proto_tree_add_subtree(homa_tree, tvb, 0,
							  COMMON_HEADER_LENGTH,
							  0, &ti,
							  "Need ACK Header");
		break;
	case HOMA_FREEZE_PACKET:
		col_set_str(pinfo->cinfo, COL_INFO, "Freeze Packet");
		homa_tree_common = proto_tree_add_subtree(homa_tree, tvb, 0,
							  COMMON_HEADER_LENGTH,
							  0, &ti,
							  "Freeze Header");
		break;
	case HOMA_BUSY_PACKET:
		col_set_str(pinfo->cinfo, COL_INFO, "Busy Packet");
		homa_tree_common = proto_tree_add_subtree(homa_tree, tvb, 0,
							  COMMON_HEADER_LENGTH,
							  0, &ti,
							  "Busy Header");
		break;
	case HOMA_UNKNOWN_PACKET:
	default:
		col_set_str(pinfo->cinfo, COL_INFO, "Unknown Packet");
		homa_tree_common = proto_tree_add_subtree(
			homa_tree, tvb, 0, COMMON_HEADER_LENGTH, 0, &ti,
			"Unknown Paket Header");
		break;
	}
	proto_tree_add_item(homa_tree_common, hf_homa_common_sport, tvb, 0, 2,
			    ENC_BIG_ENDIAN);
	proto_tree_add_item(homa_tree_common, hf_homa_common_dport, tvb, 2, 2,
			    ENC_BIG_ENDIAN);
	proto_tree_add_item(homa_tree_common, hf_homa_common_doff, tvb, 12, 1,
			    ENC_BIG_ENDIAN);
	proto_tree_add_item(homa_tree_common, hf_homa_common_type, tvb,
			    HOMA_HEADER_TYPE_OFFSET, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(homa_tree_common, hf_homa_common_sender_id, tvb, 20,
			    8, ENC_BIG_ENDIAN);

	switch (homa_packet_type) { // Fill in header fields
	case HOMA_DATA_PACKET:
		col_set_str(pinfo->cinfo, COL_INFO, "Data Packet");
		proto_tree *homa_tree_data = proto_tree_add_subtree(
			homa_tree, tvb, COMMON_HEADER_LENGTH,
			header_length - COMMON_HEADER_LENGTH, 0, &ti,
			"Data Header");
		proto_tree_add_item(homa_tree_data, hf_homa_data_message_length,
				    tvb, COMMON_HEADER_LENGTH, 4,
				    ENC_BIG_ENDIAN);
		proto_tree_add_item(homa_tree_data, hf_homa_data_incoming, tvb,
				    COMMON_HEADER_LENGTH + 4, 4,
				    ENC_BIG_ENDIAN);
		proto_tree_add_item(homa_tree_data, hf_homa_data_cutoff_version,
				    tvb, COMMON_HEADER_LENGTH + 8, 2,
				    ENC_BIG_ENDIAN);
		proto_tree_add_item(homa_tree_data, hf_homa_data_retransmit,
				    tvb, COMMON_HEADER_LENGTH + 10, 1,
				    ENC_BIG_ENDIAN);
		proto_tree_add_item(homa_tree_data, hf_homa_data_offset, tvb,
				    COMMON_HEADER_LENGTH + 12, 4,
				    ENC_BIG_ENDIAN);
		proto_tree_add_item(homa_tree_data, hf_homa_data_segment_length,
				    tvb, COMMON_HEADER_LENGTH + 16, 4,
				    ENC_BIG_ENDIAN);
		proto_tree_add_item(homa_tree_data, hf_homa_ack_client_id, tvb,
				    COMMON_HEADER_LENGTH + 20, 8,
				    ENC_BIG_ENDIAN);
		proto_tree_add_item(homa_tree_data, hf_homa_ack_client_port,
				    tvb, COMMON_HEADER_LENGTH + 28, 2,
				    ENC_BIG_ENDIAN);
		proto_tree_add_item(homa_tree_data, hf_homa_ack_server_port,
				    tvb, COMMON_HEADER_LENGTH + 30, 2,
				    ENC_BIG_ENDIAN);
		break;
	case HOMA_RESEND_PACKET:
		col_set_str(pinfo->cinfo, COL_INFO, "Resend Packet");
		proto_tree *homa_tree_resend = proto_tree_add_subtree(
			homa_tree, tvb, COMMON_HEADER_LENGTH,
			header_length - COMMON_HEADER_LENGTH, 0, &ti,
			"Resend Header");
		proto_tree_add_item(homa_tree_resend, hf_homa_resend_offset,
				    tvb, COMMON_HEADER_LENGTH, 4,
				    ENC_BIG_ENDIAN);
		proto_tree_add_item(homa_tree_resend, hf_homa_resend_length,
				    tvb, COMMON_HEADER_LENGTH + 4, 4,
				    ENC_BIG_ENDIAN);
		proto_tree_add_item(homa_tree_resend, hf_homa_resend_priority,
				    tvb, COMMON_HEADER_LENGTH + 8, 1,
				    ENC_BIG_ENDIAN);
		break;
	case HOMA_GRANT_PACKET:
		col_set_str(pinfo->cinfo, COL_INFO, "Grant Packet");
		proto_tree *homa_tree_grant = proto_tree_add_subtree(
			homa_tree, tvb, COMMON_HEADER_LENGTH,
			header_length - COMMON_HEADER_LENGTH, 0, &ti,
			"Grant Header");
		proto_tree_add_item(homa_tree_grant, hf_homa_grant_offset, tvb,
				    COMMON_HEADER_LENGTH, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(homa_tree_grant, hf_homa_grant_priority,
				    tvb, COMMON_HEADER_LENGTH + 4, 1,
				    ENC_BIG_ENDIAN);
		break;
	case HOMA_ACK_PACKET:
		col_set_str(pinfo->cinfo, COL_INFO, "ACK Packet");
		proto_tree *homa_tree_ack = proto_tree_add_subtree(
			homa_tree, tvb, COMMON_HEADER_LENGTH,
			header_length - COMMON_HEADER_LENGTH, 0, &ti,
			"ACK Header");
		proto_tree_add_item(homa_tree_ack, hf_homa_ack_num_acks, tvb,
				    COMMON_HEADER_LENGTH, 2, ENC_BIG_ENDIAN);
		break;

	case HOMA_CUTOFFS_PACKET:
		col_set_str(pinfo->cinfo, COL_INFO, "Cutoff Packet");
		proto_tree *homa_tree_cutoff = proto_tree_add_subtree(
			homa_tree, tvb, COMMON_HEADER_LENGTH,
			header_length - COMMON_HEADER_LENGTH, 0, &ti,
			"Cutoff Header");
		proto_tree_add_item(homa_tree_cutoff,
				    hf_homa_cutoff_unsched_cutoffs, tvb,
				    COMMON_HEADER_LENGTH, 32, ENC_BIG_ENDIAN);
		proto_tree_add_item(homa_tree_cutoff, hf_homa_cutoff_version,
				    tvb, COMMON_HEADER_LENGTH + 32, 2,
				    ENC_BIG_ENDIAN);
		break;
	}
	call_data_dissector(tvb_new_subset_remaining(tvb, header_length), pinfo,
			    tree);
	tvb_reported_length_remaining(tvb, header_length);
	tvb_set_reported_length(tvb, header_length);
	return tvb_reported_length(tvb);
}

static void proto_register_homa(void)
{
	static hf_register_info hf_common[] = {
		{ &hf_homa_common_sport,
		  { "Homa source port", "homa.sport", FT_UINT16, BASE_DEC, NULL,
		    0x0, NULL, HFILL } },
		{ &hf_homa_common_dport,
		  { "Homa dest port", "homa.dport", FT_UINT16, BASE_DEC, NULL,
		    0x0, NULL, HFILL } },
		{ &hf_homa_common_type,
		  { "Homa packet type", "homa.type", FT_UINT8, BASE_HEX, NULL,
		    0x0, NULL, HFILL } },
		{ &hf_homa_common_doff,
		  { "Homa data offset", "homa.doff", FT_UINT8, BASE_DEC, NULL,
		    0xF0, NULL, HFILL } },
		{ &hf_homa_common_sender_id,
		  { "Homa sender ID", "homa.id", FT_UINT64, BASE_DEC, NULL, 0x0,
		    NULL, HFILL } }
	};
	static hf_register_info hf_data[] = {
		{ &hf_homa_data_message_length,
		  { "Homa message length", "homa.length", FT_UINT32, BASE_DEC,
		    NULL, 0x0, NULL, HFILL } },
		{ &hf_homa_data_incoming,
		  { "Homa incoming", "homa.incoming", FT_UINT32, BASE_DEC, NULL,
		    0x0, NULL, HFILL } },
		{ &hf_homa_data_cutoff_version,
		  { "Homa cutoff version", "homa.cutoff_version", FT_UINT16,
		    BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_homa_data_retransmit,
		  { "Homa retransmit", "homa.retransmit", FT_UINT8, BASE_DEC,
		    NULL, 0x0, NULL, HFILL } },
		{ &hf_homa_data_offset,
		  { "Homa segment offset", "homa.offset", FT_UINT32, BASE_DEC,
		    NULL, 0x0, NULL, HFILL } },
		{ &hf_homa_data_segment_length,
		  { "Homa segment length", "homa.segment_length", FT_UINT32,
		    BASE_DEC, NULL, 0x0, NULL, HFILL } }
	};
	static hf_register_info hf_homa_ack[] = {
		{ &hf_homa_ack_client_id,
		  { "Homa client id", "homa.client_id", FT_UINT64, BASE_DEC,
		    NULL, 0x0, NULL, HFILL } },
		{ &hf_homa_ack_client_port,
		  { "Homa client port", "homa.client_port", FT_UINT16, BASE_DEC,
		    NULL, 0x0, NULL, HFILL } },
		{ &hf_homa_ack_server_port,
		  { "Homa server port", "homa.server_port", FT_UINT16, BASE_DEC,
		    NULL, 0x0, NULL, HFILL } }
	};
	static hf_register_info hf_grant[] = {
		{ &hf_homa_grant_offset,
		  { "Homa grant offset", "homa.grant_offset", FT_UINT32,
		    BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_homa_grant_priority,
		  { "Homa grant priority", "homa.grant_priority", FT_UINT8,
		    BASE_DEC, NULL, 0x0, NULL, HFILL } }
	};
	static hf_register_info hf_resend[] = {
		{ &hf_homa_resend_offset,
		  { "Homa resend offset", "homa.resend_offset", FT_UINT32,
		    BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_homa_resend_length,
		  { "Homa resend length", "homa.resend_length", FT_UINT32,
		    BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_homa_resend_priority,
		  { "Homa resend priority", "homa.resend_priority", FT_UINT8,
		    BASE_DEC, NULL, 0x0, NULL, HFILL } }
	};

	static hf_register_info hf_header_ack[] = {
		{ &hf_homa_ack_num_acks,
		  { "Homa number of acks", "homa.num_acks", FT_UINT16, BASE_DEC,
		    NULL, 0x0, NULL, HFILL } },
	};

	static hf_register_info hf_cutoffs[] = {
		{ &hf_homa_cutoff_unsched_cutoffs,
		  { "Homa unscheduled cutoffs", "homa.unsched_cutoffs",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_homa_cutoff_version,
		  { "Homa cutoff version", "homa.cutoff.cutoff_version",
		    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	};

	/* Setup protocol subtree array */
	static int *ett[] = { &ett_homa_common };

	proto_homa = proto_register_protocol("Homa Protocol", /* name */
					     "Homa", /* short_name */
					     "homa" /* filter_name */
	);

	proto_register_field_array(proto_homa, hf_common,
				   array_length(hf_common));
	proto_register_field_array(proto_homa, hf_data, array_length(hf_data));
	proto_register_field_array(proto_homa, hf_homa_ack,
				   array_length(hf_homa_ack));
	proto_register_field_array(proto_homa, hf_grant,
				   array_length(hf_grant));
	proto_register_field_array(proto_homa, hf_resend,
				   array_length(hf_resend));
	proto_register_field_array(proto_homa, hf_header_ack,
				   array_length(hf_header_ack));
	proto_register_field_array(proto_homa, hf_cutoffs,
				   array_length(hf_cutoffs));
	proto_register_subtree_array(ett, array_length(ett));
}

static void proto_reg_handoff_homa(void)
{
	static dissector_handle_t homa_handle;

	homa_handle = create_dissector_handle(dissect_homa, proto_homa);
	dissector_add_uint("ip.proto", HOMA_PROTO, homa_handle);
}

WS_DLL_PUBLIC void plugin_register(void)
{
	static proto_plugin protoPlugin;

	protoPlugin.register_protoinfo = proto_register_homa;
	protoPlugin.register_handoff = proto_reg_handoff_homa;
	proto_register_plugin(&protoPlugin);
}
