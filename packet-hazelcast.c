#include "config.h"

#include <epan/packet.h>
#include <gmodule.h>

#define HAZELCAST_TCP_PORTS "5701,5702,5703"
#define HAZELCAST_MULTICAST_PORT 54327

//             PACKET HEADER FLAGS
//
// Flags are dispatched against in a cascade:
// 1. URGENT (bit 4)
// 2. Packet type (bits 0, 2, 5)
// 3. Flags specific to a given packet type (bits 1, 6)
// 4. 4.x flag (bit 7)

// Packet type bit 0. Historically the OPERATION type flag.
#define FLAG_TYPE0              0x01
// Packet type bit 1. Historically the EVENT type flag.
#define FLAG_OP_RESPONSE        0x02
// Packet type bit 1. Historically the EVENT type flag.
#define FLAG_TYPE1              0x04
// Marks a Jet packet as Flow control
#define FLAG_JET_FLOW_CONTROL   0x04
#define FLAG_URGENT             0x10
// Packet type bit 2. Historically the BIND type flag.
#define FLAG_TYPE2              0x20
// Marks an Operation packet as Operation control (like invocation-heartbeats)
#define FLAG_OP_CONTROL         0x40
// Marks a packet as sent by a 4.x member
#define FLAG_4_0                0x80

static const value_string packet_type_names[] = {
    { 1, "Operation (1)" },
    { 2, "Event (2)" },
    { 3, "Jet (3)" },
    { 4, "Server control (4)" }
};

static const value_string serializer_names[] = {
		{ 0, "CONSTANT_TYPE_NULL" },
		{ -1, "CONSTANT_TYPE_PORTABLE" },
		{ -2, "CONSTANT_TYPE_DATA_SERIALIZABLE" },
		{ -3, "CONSTANT_TYPE_BYTE" },
		{ -4, "CONSTANT_TYPE_BOOLEAN" },
		{ -5, "CONSTANT_TYPE_CHAR" },
		{ -6, "CONSTANT_TYPE_SHORT" },
		{ -7, "CONSTANT_TYPE_INTEGER" },
		{ -8, "CONSTANT_TYPE_LONG" },
		{ -9, "CONSTANT_TYPE_FLOAT" },
		{ -10, "CONSTANT_TYPE_DOUBLE" },
		{ -11, "CONSTANT_TYPE_STRING" },
		{ -12, "CONSTANT_TYPE_BYTE_ARRAY" },
		{ -13, "CONSTANT_TYPE_BOOLEAN_ARRAY" },
		{ -14, "CONSTANT_TYPE_CHAR_ARRAY" },
		{ -15, "CONSTANT_TYPE_SHORT_ARRAY" },
		{ -16, "CONSTANT_TYPE_INTEGER_ARRAY" },
		{ -17, "CONSTANT_TYPE_LONG_ARRAY" },
		{ -18, "CONSTANT_TYPE_FLOAT_ARRAY" },
		{ -19, "CONSTANT_TYPE_DOUBLE_ARRAY" },
		{ -20, "CONSTANT_TYPE_STRING_ARRAY" },
		{ -21, "CONSTANT_TYPE_UUID" },
		{ -22, "CONSTANT_TYPE_SIMPLE_ENTRY" },
		{ -23, "CONSTANT_TYPE_SIMPLE_IMMUTABLE_ENTRY" },
		// ------------------------------------------------------------
		// DEFAULT SERIALIZERS
		{ -24, "JAVA_DEFAULT_TYPE_CLASS" },
		{ -25, "JAVA_DEFAULT_TYPE_DATE" },
		{ -26, "JAVA_DEFAULT_TYPE_BIG_INTEGER" },
		{ -27, "JAVA_DEFAULT_TYPE_BIG_DECIMAL" },
		{ -28, "JAVA_DEFAULT_TYPE_ARRAY" },
		{ -29, "JAVA_DEFAULT_TYPE_ARRAY_LIST" },
		{ -30, "JAVA_DEFAULT_TYPE_LINKED_LIST" },
		{ -31, "JAVA_DEFAULT_TYPE_COPY_ON_WRITE_ARRAY_LIST" },
		{ -32, "JAVA_DEFAULT_TYPE_HASH_MAP" },
		{ -33, "JAVA_DEFAULT_TYPE_CONCURRENT_SKIP_LIST_MAP" },
		{ -34, "JAVA_DEFAULT_TYPE_CONCURRENT_HASH_MAP" },
		{ -35, "JAVA_DEFAULT_TYPE_LINKED_HASH_MAP" },
		{ -36, "JAVA_DEFAULT_TYPE_TREE_MAP" },
		{ -37, "JAVA_DEFAULT_TYPE_HASH_SET" },
		{ -38, "JAVA_DEFAULT_TYPE_TREE_SET" },
		{ -39, "JAVA_DEFAULT_TYPE_LINKED_HASH_SET" },
		{ -40, "JAVA_DEFAULT_TYPE_COPY_ON_WRITE_ARRAY_SET" },
		{ -41, "JAVA_DEFAULT_TYPE_CONCURRENT_SKIP_LIST_SET" },
		{ -42, "JAVA_DEFAULT_TYPE_ARRAY_DEQUE" },
		{ -43, "JAVA_DEFAULT_TYPE_LINKED_BLOCKING_QUEUE" },
		{ -44, "JAVA_DEFAULT_TYPE_ARRAY_BLOCKING_QUEUE" },
		{ -45, "JAVA_DEFAULT_TYPE_PRIORITY_BLOCKING_QUEUE" },
		{ -46, "JAVA_DEFAULT_TYPE_DELAY_QUEUE" },
		{ -47, "JAVA_DEFAULT_TYPE_SYNCHRONOUS_QUEUE" },
		{ -48, "JAVA_DEFAULT_TYPE_LINKED_TRANSFER_QUEUE" },
		{ -49, "JAVA_DEFAULT_TYPE_PRIORITY_QUEUE" },
		{ -50, "JAVA_DEFAULT_TYPE_OPTIONAL" },
		{ -51, "JAVA_DEFAULT_TYPE_LOCALDATE" },
		{ -52, "JAVA_DEFAULT_TYPE_LOCALTIME" },
		{ -53, "JAVA_DEFAULT_TYPE_LOCALDATETIME" },
		{ -54, "JAVA_DEFAULT_TYPE_OFFSETDATETIME" },
		{ -55, "TYPE_COMPACT" },
		{ -56, "TYPE_COMPACT_WITH_SCHEMA" },
		// ------------------------------------------------------------
		// JAVA SERIALIZATION
		{ -100, "JAVA_DEFAULT_TYPE_SERIALIZABLE" },
		{ -101, "JAVA_DEFAULT_TYPE_EXTERNALIZABLE" },
		// ------------------------------------------------------------
		// LANGUAGE SPECIFIC SERIALIZERS
		// USED BY CLIENTS (Not deserialized by server)
		{ -110, "CSHARP_CLR_SERIALIZATION_TYPE" },
		{ -120, "PYTHON_PICKLE_SERIALIZATION_TYPE" },
		{ -130, "JAVASCRIPT_JSON_SERIALIZATION_TYPE" },
		{ -140, "GO_GOB_SERIALIZATION_TYPE" },
		// ------------------------------------------------------------
		// HIBERNATE SERIALIZERS
		{ -200, "HIBERNATE3_TYPE_HIBERNATE_CACHE_KEY" },
		{ -201, "HIBERNATE3_TYPE_HIBERNATE_CACHE_ENTRY" },
		{ -202, "HIBERNATE4_TYPE_HIBERNATE_CACHE_KEY" },
		{ -203, "HIBERNATE4_TYPE_HIBERNATE_CACHE_ENTRY" },
		{ -204, "HIBERNATE5_TYPE_HIBERNATE_CACHE_KEY" },
		{ -205, "HIBERNATE5_TYPE_HIBERNATE_CACHE_ENTRY" },
		{ -206, "HIBERNATE5_TYPE_HIBERNATE_NATURAL_ID_KEY" },
		//--------------------------------------------------------------
		// RESERVED FOR JET -300 to -400
		{ -300, "JET_SERIALIZER_FIRST" },
		{ -399, "JET_SERIALIZER_LAST" }
};


static int proto_hazelcast = -1;

static gchar *protocol_header = NULL;

static int hf_hazelcast_protocol_header = -1;
static int hf_hazelcast_packet_version = -1;
static int hf_hazelcast_packet_flags = -1;
static int hf_hazelcast_packet_partition_id = -1;
static int hf_hazelcast_packet_payload_size = -1;

static int hf_hazelcast_payload_hash = -1;
static int hf_hazelcast_payload_serializer = -1;
static int hf_hazelcast_payload_data = -1;

static int hf_hazelcast_packet_flag_type0 = -1;
static int hf_hazelcast_packet_flag_op_response = -1;
static int hf_hazelcast_packet_flag_type1 = -1;
static int hf_hazelcast_packet_flag_urgent = -1;
static int hf_hazelcast_packet_flag_type2 = -1;
static int hf_hazelcast_packet_flag_op_control = -1;
static int hf_hazelcast_packet_flag_4_0 = -1;


static int hf_hazelcast_unknown_bytes = -1;

static gint ett_hazelcast = -1;

static int
dissect_hazelcast(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Hazelcast");
    /* Clear the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_hazelcast, tvb, 0, -1, ENC_NA);
    proto_tree *hazelcast_tree = proto_item_add_subtree(ti, ett_hazelcast);

    static const int * packet_flag_fields[] = {
        &hf_hazelcast_packet_flag_type0,
        &hf_hazelcast_packet_flag_op_response,
        &hf_hazelcast_packet_flag_type1,
        &hf_hazelcast_packet_flag_urgent,
        &hf_hazelcast_packet_flag_type2,
        &hf_hazelcast_packet_flag_op_control,
        &hf_hazelcast_packet_flag_4_0,
        NULL
    };

    guint packet_len = tvb_captured_length(tvb);

    if (3 == packet_len) {
    	protocol_header = (gchar *)tvb_get_string_enc(wmem_packet_scope(), tvb, 0, 3, ENC_ASCII|ENC_NA);

    	col_add_fstr(pinfo->cinfo, COL_INFO, "Header %s", protocol_header);

        proto_tree_add_item(hazelcast_tree, hf_hazelcast_protocol_header, tvb, 0, 3, ENC_BIG_ENDIAN);
    } else  if (11 <= packet_len) {

    	guint packet_flags = tvb_get_ntohs(tvb, 1);
    	guint packet_type = (packet_flags & FLAG_TYPE0)
    				| (packet_flags & FLAG_TYPE1) >> 1
    		        | (packet_flags & FLAG_TYPE2) >> 3;
        col_add_fstr(pinfo->cinfo, COL_INFO, "Type: %s",
                     val_to_str(packet_type, packet_type_names, "Unknown (0x%02x)"));

    	gint offset = 0;
        proto_tree_add_item(hazelcast_tree, hf_hazelcast_packet_version, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_bitmask(hazelcast_tree, tvb, offset, hf_hazelcast_packet_flags, ett_hazelcast, packet_flag_fields, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(hazelcast_tree, hf_hazelcast_packet_partition_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        int payload_size = tvb_get_ntohil(tvb, offset);
        proto_tree_add_item(hazelcast_tree, hf_hazelcast_packet_payload_size, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(hazelcast_tree, hf_hazelcast_payload_hash, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(hazelcast_tree, hf_hazelcast_payload_serializer, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(hazelcast_tree, hf_hazelcast_payload_data, tvb, offset, -1, ENC_BIG_ENDIAN);
        offset += 4;
    } else {
    	proto_tree_add_item(hazelcast_tree, hf_hazelcast_unknown_bytes, tvb, 0, -1, ENC_BIG_ENDIAN);
    }

    return packet_len;
}

void
proto_register_hazelcast(void)
{
	static hf_register_info hf[] = {
	    { &hf_hazelcast_protocol_header,
	        { "Protocol header", "hazelcast.protocol.header",
	        FT_STRING, BASE_NONE,
	        NULL, 0x0,
	        NULL, HFILL }
	    },
	    { &hf_hazelcast_packet_version,
	        { "Packet version", "hazelcast.packet.version",
	        FT_UINT8, BASE_DEC,
	        NULL, 0x0,
	        NULL, HFILL }
	    },
	    { &hf_hazelcast_packet_flags,
	        { "Packet flags", "hazelcast.packet.flags",
	        FT_UINT16, BASE_DEC,
	        NULL, 0x0,
	        NULL, HFILL }
	    },
	    { &hf_hazelcast_packet_partition_id,
	        { "Packet partition ID", "hazelcast.packet.partition",
	        FT_INT32, BASE_DEC,
	        NULL, 0x0,
	        NULL, HFILL }
	    },
	    { &hf_hazelcast_packet_payload_size,
	        { "Payload size", "hazelcast.packet.payload.size",
	        FT_INT32, BASE_DEC,
	        NULL, 0x0,
	        NULL, HFILL }
	    },
	    { &hf_hazelcast_payload_hash,
	        { "Payload hash", "hazelcast.payload.hash",
	        FT_INT32, BASE_DEC,
	        NULL, 0x0,
	        NULL, HFILL }
	    },
	    { &hf_hazelcast_payload_serializer,
	        { "Payload serializer", "hazelcast.payload.serializer",
	        FT_INT32, BASE_DEC,
	        VALS(serializer_names), 0x0,
	        NULL, HFILL }
	    },
	    { &hf_hazelcast_payload_data,
	        { "Payload data", "hazelcast.payload.data",
	        FT_BYTES, BASE_NONE,
	        NULL, 0x0,
	        NULL, HFILL }
	    },
	    { &hf_hazelcast_unknown_bytes,
	        { "Unknown bytes", "hazelcast.unknown.bytes",
	        FT_BYTES, BASE_NONE,
	        NULL, 0x0,
	        NULL, HFILL }
	    },
	    { &hf_hazelcast_packet_flag_type0,
	        { "Type0", "hazelcast.packet.flag.type0",
	        FT_BOOLEAN, 8,
	        NULL, FLAG_TYPE0,
	        NULL, HFILL }
	    },
	    { &hf_hazelcast_packet_flag_op_response,
	        { "Op Response", "hazelcast.packet.flag.op_response",
	        FT_BOOLEAN, 8,
	        NULL, FLAG_OP_RESPONSE,
	        NULL, HFILL }
	    },
	    { &hf_hazelcast_packet_flag_type1,
	        { "Type1", "hazelcast.packet.flag.type1",
	        FT_BOOLEAN, 8,
	        NULL, FLAG_TYPE1,
	        NULL, HFILL }
	    },
	    { &hf_hazelcast_packet_flag_urgent,
	        { "Urgent", "hazelcast.packet.flag.urgent",
	        FT_BOOLEAN, 8,
	        NULL, FLAG_URGENT,
	        NULL, HFILL }
	    },
	    { &hf_hazelcast_packet_flag_type2,
	        { "Type2", "hazelcast.packet.flag.type2",
	        FT_BOOLEAN, 8,
	        NULL, FLAG_TYPE2,
	        NULL, HFILL }
	    },
	    { &hf_hazelcast_packet_flag_op_control,
	        { "Op Control", "hazelcast.packet.flag.op_control",
	        FT_BOOLEAN, 8,
	        NULL, FLAG_OP_CONTROL,
	        NULL, HFILL }
	    },
	    { &hf_hazelcast_packet_flag_4_0,
	        { "4.0", "hazelcast.packet.flag.4_0",
	        FT_BOOLEAN, 8,
	        NULL, FLAG_4_0,
	        NULL, HFILL }
	    }
	};

    static gint *ett[] = {
        &ett_hazelcast
    };

    proto_hazelcast = proto_register_protocol (
        "Hazelcast Member Protocol", /* name        */
        "Hazelcast",          /* short_name  */
        "hazelcast"           /* filter_name */
        );
    proto_register_field_array(proto_hazelcast, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_hazelcast(void)
{
	range_t *hazelcast_port_range;

	range_convert_str(wmem_epan_scope(), &hazelcast_port_range, HAZELCAST_TCP_PORTS, 0xFF);

    static dissector_handle_t hazelcast_handle;

    hazelcast_handle = create_dissector_handle(dissect_hazelcast, proto_hazelcast);
//    dissector_add_uint_range("tcp.port", hazelcast_port_range, hazelcast_handle);
    dissector_add_uint("tcp.port", 5701, hazelcast_handle);
    dissector_add_uint("tcp.port", 5702, hazelcast_handle);
    dissector_add_uint("tcp.port", 5703, hazelcast_handle);
    dissector_add_uint("udp.port", HAZELCAST_MULTICAST_PORT, hazelcast_handle);
}
