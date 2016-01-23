/* packet-userlog.c
 * Routines for userlog protocol packet disassembly
 * By Jun Wang <sdn_app@163.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>

#define UserLog_PORT 9020

static int proto_userlog = -1 ;

void proto_register_userlog(void);
void proto_reg_handoff_userlog(void);

static gint ett_userlog            = -1;
static gint ett_userlog_header     = -1;
static gint ett_userlog_log        = -1;

static int hf_userlog_version      = -1;
static int hf_userlog_logtype      = -1;
static int hf_userlog_count        = -1;
static int hf_userlog_timestamp    = -1;

static int hf_userlog_proto        = -1;
static int hf_userlog_Operator     = -1;
static int hf_userlog_IPVerion     = -1;
static int hf_userlog_IPToS        = -1;

static int hf_userlog_SourceIP     = -1;
static int hf_userlog_SrcNatIP     = -1;
static int hf_userlog_DestIP       = -1;
static int hf_userlog_DestNatIP    = -1;
static int hf_userlog_SrcPort      = -1;
static int hf_userlog_SrcNatPort   = -1;
static int hf_userlog_DestPort     = -1;
static int hf_userlog_DestNatPort  = -1;

static int hf_userlog_StartTime    = -1;
static int hf_userlog_EndTime      = -1;

static int hf_userlog_InTotalPkg   = -1;
static int hf_userlog_InTotalByte  = -1;
static int hf_userlog_OutTotalPkg  = -1;
static int hf_userlog_OutTotalByte = -1;

static int hf_userlog_Reserved1    = -1;
static int hf_userlog_Reserved2    = -1;
static int hf_userlog_Reserved3    = -1;

static const value_string version[] = {
{ 1, "V1" },
{ 3, "V3" },
{ 0, NULL }
};

static const value_string logtype[] = {
{ 1, "NAT" },
{ 2, "BAS" },
{ 4, "Flow" },
{ 0, NULL }
};

static const value_string protocol[] = {
{ 1, "ICMP" },
{ 6, "TCP" },
{ 17, "UDP" },
{ 89, "OSPF" },
{ 112, "VRRP" },
{ 0, NULL }
};

static const value_string Operator[] = {
{ 1, "normal close flow" },
{ 2, "timeout" },
{ 3, "clear flow" },
{ 4, "overflow" },
{ 5, "nat static" },
{ 6, "time data threshold" },
{ 7, "flow delete" },
{ 8, "flow create" },
{ 0, NULL }
};


static int
dissect_userlog(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	gint offset    = 0;
	gint log_max   = 1;
	gint log_count = 1;
	gint log_type  = 1;
	log_max        = tvb_get_ntohs(tvb, 2);
	log_type       = tvb_get_guint8(tvb, 1);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "UserLog");
	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo,COL_INFO);
	col_add_fstr(pinfo->cinfo, COL_INFO, "LogType = %s",
				val_to_str(log_type, logtype, "Unknown (0x%02x)"));


	if (tree) {

		proto_item *ti = NULL;
		proto_tree *userlog_header = NULL;
		proto_tree *userlog_log = NULL;

		ti = proto_tree_add_item(tree, proto_userlog, tvb, 0, -1, ENC_NA);
		proto_item_append_text(ti, ", Log Count = %d", log_max);

		userlog_header = proto_item_add_subtree(ti, ett_userlog);


		userlog_header = proto_tree_add_subtree(ti, tvb, 0, 16, ett_userlog_header, NULL, "UserLog Header");
		proto_tree_add_item(userlog_header, hf_userlog_version, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		proto_tree_add_item(userlog_header, hf_userlog_logtype, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		proto_tree_add_item(userlog_header, hf_userlog_count, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		proto_tree_add_item(userlog_header, hf_userlog_timestamp, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;


		while ( log_count <= log_max)
		{
			offset = 16 + 64 * (log_count - 1);

			userlog_log = proto_tree_add_subtree(ti, tvb, offset, 64, ett_userlog_log, NULL, "");
			proto_item_append_text(userlog_log, "UserLog No.%d", log_count);

			proto_tree_add_item(userlog_log, hf_userlog_proto, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			proto_tree_add_item(userlog_log, hf_userlog_Operator, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			proto_tree_add_item(userlog_log, hf_userlog_IPVerion, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			proto_tree_add_item(userlog_log, hf_userlog_IPToS, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			proto_tree_add_item(userlog_log, hf_userlog_SourceIP, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(userlog_log, hf_userlog_SrcNatIP, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(userlog_log, hf_userlog_DestIP, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(userlog_log, hf_userlog_DestNatIP, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(userlog_log, hf_userlog_SrcPort, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			proto_tree_add_item(userlog_log, hf_userlog_SrcNatPort, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			proto_tree_add_item(userlog_log, hf_userlog_DestPort, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			proto_tree_add_item(userlog_log, hf_userlog_DestNatPort, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;

			proto_tree_add_item(userlog_log, hf_userlog_StartTime, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(userlog_log, hf_userlog_EndTime, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			proto_tree_add_item(userlog_log, hf_userlog_InTotalPkg, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(userlog_log, hf_userlog_InTotalByte, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(userlog_log, hf_userlog_OutTotalPkg, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(userlog_log, hf_userlog_OutTotalByte, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			proto_tree_add_item(userlog_log, hf_userlog_Reserved1, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(userlog_log, hf_userlog_Reserved2, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(userlog_log, hf_userlog_Reserved3, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			log_count++;

		}
	}

    return tvb_captured_length(tvb);
}

void
proto_register_userlog(void)
{
    static hf_register_info hf[] = {
		{ &hf_userlog_version,
			{ "Version  ", "userlog.version",
			FT_UINT8, BASE_DEC,
			VALS(version), 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_logtype,
			{ "LogType  ", "userlog.logtype",
			FT_UINT8, BASE_DEC,
			VALS(logtype), 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_count,
			{ "LogCount ", "userlog.count",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_timestamp,
			{ "TimeStamp", "userlog.timestamp",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
			NULL, 0x0,
			NULL, HFILL }
		},

        /*--userlog
        */
		{ &hf_userlog_proto,
			{ "Protocol ", "userlog.proto",
			FT_UINT8, BASE_DEC,
			VALS(protocol), 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_Operator,
			{ "Operator ", "userlog.Operator",
			FT_UINT8, BASE_DEC,
			VALS(Operator), 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_IPVerion,
			{ "IP Verion", "userlog.IPVerion",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_IPToS,
			{ "IP ToS   ", "userlog.IPToS",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_SourceIP,
			{ "Source-IP          ", "userlog.SourceIP",
			FT_IPv4, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_SrcNatIP,
			{ "Source-NAT-IP      ", "userlog.Source-NAT-IP",
			FT_IPv4, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_DestIP,
			{ "Destnation-IP      ", "userlog.Destnation-IP",
			FT_IPv4, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_DestNatIP,
			{ "Destnation-NAT-IP  ", "userlog.Destnation-NAT-IP",
			FT_IPv4, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_SrcPort,
			{ "Source-Port        ", "userlog.Source-Port",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_SrcNatPort,
			{ "Source-NAT-Port    ", "userlog.Source-NAT-Port",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_DestPort,
			{ "Destnation-Port    ", "userlog.Destnation-Port",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_DestNatPort,
			{ "Destnation-NAT-Port", "userlog.Destnation-NAT-Port",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_StartTime,
			{ "StartTime", "userlog.StartTime",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_EndTime,
			{ "EndTime  ", "userlog.EndTime",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_InTotalPkg,
			{ "InTotalPkg  ", "userlog.InTotalPkg",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_InTotalByte,
			{ "InTotalByte ", "userlog.InTotalByte",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_OutTotalPkg,
			{ "OutTotalPkg ", "userlog.OutTotalPkg",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_OutTotalByte,
			{ "OutTotalByte", "userlog.OutTotalByte",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_Reserved1,
			{ "Reserved1   ", "userlog.Reserved1",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_Reserved2,
			{ "Reserved2   ", "userlog.Reserved2",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_Reserved3,
			{ "Reserved3   ", "userlog.Reserved3",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		}

	};


	/* Setup protocol subtree array */

	static gint *ett[] = {
		&ett_userlog,
		&ett_userlog_header,
		&ett_userlog_log
	};


	proto_userlog = proto_register_protocol("UserLog Protocol",  /* name         */
                                            "UserLog",           /* short name   */
                                            "userlog"            /* abbrev       */
											);

	proto_register_field_array(proto_userlog, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_userlog(void)
{
	dissector_handle_t userlog_handle;
	userlog_handle = create_dissector_handle(dissect_userlog, proto_userlog);
	dissector_add_uint("udp.port", UserLog_PORT, userlog_handle);
}


