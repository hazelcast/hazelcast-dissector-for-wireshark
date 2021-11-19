#include "config.h"

#include "packet-hazelcast.h"
#include <epan/packet.h>
#include <epan/dissectors/packet-tcp.h>
#include <gmodule.h>

#define HAZELCAST_TCP_PORT1 5701
#define HAZELCAST_TCP_PORT2 5702
#define HAZELCAST_TCP_PORT3 5703

// https://github.com/hazelcast/hazelcast/blob/5.0/hazelcast/src/main/java/com/hazelcast/internal/nio/Packet.java#L273-L366

static const value_string packet_type_names[] = {
    { 1, "Operation (1)" },
    { 2, "Event (2)" },
    { 3, "Jet (3)" },
    { 4, "Server control (4)" }
};

// https://github.com/hazelcast/hazelcast/blob/5.0/hazelcast/src/main/java/com/hazelcast/internal/serialization/impl/SerializationConstants.java

static const value_string serializer_names[] = {
		{ CONSTANT_TYPE_NULL, "CONSTANT_TYPE_NULL" },
		{ CONSTANT_TYPE_PORTABLE, "CONSTANT_TYPE_PORTABLE" },
		{ CONSTANT_TYPE_DATA_SERIALIZABLE, "CONSTANT_TYPE_DATA_SERIALIZABLE" },
		{ CONSTANT_TYPE_BYTE, "CONSTANT_TYPE_BYTE" },
		{ CONSTANT_TYPE_BOOLEAN, "CONSTANT_TYPE_BOOLEAN" },
		{ CONSTANT_TYPE_CHAR, "CONSTANT_TYPE_CHAR" },
		{ CONSTANT_TYPE_SHORT, "CONSTANT_TYPE_SHORT" },
		{ CONSTANT_TYPE_INTEGER, "CONSTANT_TYPE_INTEGER" },
		{ CONSTANT_TYPE_LONG, "CONSTANT_TYPE_LONG" },
		{ CONSTANT_TYPE_FLOAT, "CONSTANT_TYPE_FLOAT" },
		{ CONSTANT_TYPE_DOUBLE, "CONSTANT_TYPE_DOUBLE" },
		{ CONSTANT_TYPE_STRING, "CONSTANT_TYPE_STRING" },
		{ CONSTANT_TYPE_BYTE_ARRAY, "CONSTANT_TYPE_BYTE_ARRAY" },
		{ CONSTANT_TYPE_BOOLEAN_ARRAY, "CONSTANT_TYPE_BOOLEAN_ARRAY" },
		{ CONSTANT_TYPE_CHAR_ARRAY, "CONSTANT_TYPE_CHAR_ARRAY" },
		{ CONSTANT_TYPE_SHORT_ARRAY, "CONSTANT_TYPE_SHORT_ARRAY" },
		{ CONSTANT_TYPE_INTEGER_ARRAY, "CONSTANT_TYPE_INTEGER_ARRAY" },
		{ CONSTANT_TYPE_LONG_ARRAY, "CONSTANT_TYPE_LONG_ARRAY" },
		{ CONSTANT_TYPE_FLOAT_ARRAY, "CONSTANT_TYPE_FLOAT_ARRAY" },
		{ CONSTANT_TYPE_DOUBLE_ARRAY, "CONSTANT_TYPE_DOUBLE_ARRAY" },
		{ CONSTANT_TYPE_STRING_ARRAY, "CONSTANT_TYPE_STRING_ARRAY" },
		{ CONSTANT_TYPE_UUID, "CONSTANT_TYPE_UUID" },
		{ CONSTANT_TYPE_SIMPLE_ENTRY, "CONSTANT_TYPE_SIMPLE_ENTRY" },
		{ CONSTANT_TYPE_SIMPLE_IMMUTABLE_ENTRY, "CONSTANT_TYPE_SIMPLE_IMMUTABLE_ENTRY" },
		// ------------------------------------------------------------
		// DEFAULT SERIALIZERS
		{ JAVA_DEFAULT_TYPE_CLASS, "JAVA_DEFAULT_TYPE_CLASS" },
		{ JAVA_DEFAULT_TYPE_DATE, "JAVA_DEFAULT_TYPE_DATE" },
		{ JAVA_DEFAULT_TYPE_BIG_INTEGER, "JAVA_DEFAULT_TYPE_BIG_INTEGER" },
		{ JAVA_DEFAULT_TYPE_BIG_DECIMAL, "JAVA_DEFAULT_TYPE_BIG_DECIMAL" },
		{ JAVA_DEFAULT_TYPE_ARRAY, "JAVA_DEFAULT_TYPE_ARRAY" },
		{ JAVA_DEFAULT_TYPE_ARRAY_LIST, "JAVA_DEFAULT_TYPE_ARRAY_LIST" },
		{ JAVA_DEFAULT_TYPE_LINKED_LIST, "JAVA_DEFAULT_TYPE_LINKED_LIST" },
		{ JAVA_DEFAULT_TYPE_COPY_ON_WRITE_ARRAY_LIST, "JAVA_DEFAULT_TYPE_COPY_ON_WRITE_ARRAY_LIST" },
		{ JAVA_DEFAULT_TYPE_HASH_MAP, "JAVA_DEFAULT_TYPE_HASH_MAP" },
		{ JAVA_DEFAULT_TYPE_CONCURRENT_SKIP_LIST_MAP, "JAVA_DEFAULT_TYPE_CONCURRENT_SKIP_LIST_MAP" },
		{ JAVA_DEFAULT_TYPE_CONCURRENT_HASH_MAP, "JAVA_DEFAULT_TYPE_CONCURRENT_HASH_MAP" },
		{ JAVA_DEFAULT_TYPE_LINKED_HASH_MAP, "JAVA_DEFAULT_TYPE_LINKED_HASH_MAP" },
		{ JAVA_DEFAULT_TYPE_TREE_MAP, "JAVA_DEFAULT_TYPE_TREE_MAP" },
		{ JAVA_DEFAULT_TYPE_HASH_SET, "JAVA_DEFAULT_TYPE_HASH_SET" },
		{ JAVA_DEFAULT_TYPE_TREE_SET, "JAVA_DEFAULT_TYPE_TREE_SET" },
		{ JAVA_DEFAULT_TYPE_LINKED_HASH_SET, "JAVA_DEFAULT_TYPE_LINKED_HASH_SET" },
		{ JAVA_DEFAULT_TYPE_COPY_ON_WRITE_ARRAY_SET, "JAVA_DEFAULT_TYPE_COPY_ON_WRITE_ARRAY_SET" },
		{ JAVA_DEFAULT_TYPE_CONCURRENT_SKIP_LIST_SET, "JAVA_DEFAULT_TYPE_CONCURRENT_SKIP_LIST_SET" },
		{ JAVA_DEFAULT_TYPE_ARRAY_DEQUE, "JAVA_DEFAULT_TYPE_ARRAY_DEQUE" },
		{ JAVA_DEFAULT_TYPE_LINKED_BLOCKING_QUEUE, "JAVA_DEFAULT_TYPE_LINKED_BLOCKING_QUEUE" },
		{ JAVA_DEFAULT_TYPE_ARRAY_BLOCKING_QUEUE, "JAVA_DEFAULT_TYPE_ARRAY_BLOCKING_QUEUE" },
		{ JAVA_DEFAULT_TYPE_PRIORITY_BLOCKING_QUEUE, "JAVA_DEFAULT_TYPE_PRIORITY_BLOCKING_QUEUE" },
		{ JAVA_DEFAULT_TYPE_DELAY_QUEUE, "JAVA_DEFAULT_TYPE_DELAY_QUEUE" },
		{ JAVA_DEFAULT_TYPE_SYNCHRONOUS_QUEUE, "JAVA_DEFAULT_TYPE_SYNCHRONOUS_QUEUE" },
		{ JAVA_DEFAULT_TYPE_LINKED_TRANSFER_QUEUE, "JAVA_DEFAULT_TYPE_LINKED_TRANSFER_QUEUE" },
		{ JAVA_DEFAULT_TYPE_PRIORITY_QUEUE, "JAVA_DEFAULT_TYPE_PRIORITY_QUEUE" },
		{ JAVA_DEFAULT_TYPE_OPTIONAL, "JAVA_DEFAULT_TYPE_OPTIONAL" },
		{ JAVA_DEFAULT_TYPE_LOCALDATE, "JAVA_DEFAULT_TYPE_LOCALDATE" },
		{ JAVA_DEFAULT_TYPE_LOCALTIME, "JAVA_DEFAULT_TYPE_LOCALTIME" },
		{ JAVA_DEFAULT_TYPE_LOCALDATETIME, "JAVA_DEFAULT_TYPE_LOCALDATETIME" },
		{ JAVA_DEFAULT_TYPE_OFFSETDATETIME, "JAVA_DEFAULT_TYPE_OFFSETDATETIME" },
		{ TYPE_COMPACT, "TYPE_COMPACT" },
		{ TYPE_COMPACT_WITH_SCHEMA, "TYPE_COMPACT_WITH_SCHEMA" },
		// ------------------------------------------------------------
		// JAVA SERIALIZATION
		{ JAVA_DEFAULT_TYPE_SERIALIZABLE, "JAVA_DEFAULT_TYPE_SERIALIZABLE" },
		{ JAVA_DEFAULT_TYPE_EXTERNALIZABLE, "JAVA_DEFAULT_TYPE_EXTERNALIZABLE" },
		// ------------------------------------------------------------
		// LANGUAGE SPECIFIC SERIALIZERS
		// USED BY CLIENTS (Not deserialized by server)
		{ CSHARP_CLR_SERIALIZATION_TYPE, "CSHARP_CLR_SERIALIZATION_TYPE" },
		{ PYTHON_PICKLE_SERIALIZATION_TYPE, "PYTHON_PICKLE_SERIALIZATION_TYPE" },
		{ JAVASCRIPT_JSON_SERIALIZATION_TYPE, "JAVASCRIPT_JSON_SERIALIZATION_TYPE" },
		{ GO_GOB_SERIALIZATION_TYPE, "GO_GOB_SERIALIZATION_TYPE" },
		// ------------------------------------------------------------
		// HIBERNATE SERIALIZERS
		{ HIBERNATE3_TYPE_HIBERNATE_CACHE_KEY, "HIBERNATE3_TYPE_HIBERNATE_CACHE_KEY" },
		{ HIBERNATE3_TYPE_HIBERNATE_CACHE_ENTRY, "HIBERNATE3_TYPE_HIBERNATE_CACHE_ENTRY" },
		{ HIBERNATE4_TYPE_HIBERNATE_CACHE_KEY, "HIBERNATE4_TYPE_HIBERNATE_CACHE_KEY" },
		{ HIBERNATE4_TYPE_HIBERNATE_CACHE_ENTRY, "HIBERNATE4_TYPE_HIBERNATE_CACHE_ENTRY" },
		{ HIBERNATE5_TYPE_HIBERNATE_CACHE_KEY, "HIBERNATE5_TYPE_HIBERNATE_CACHE_KEY" },
		{ HIBERNATE5_TYPE_HIBERNATE_CACHE_ENTRY, "HIBERNATE5_TYPE_HIBERNATE_CACHE_ENTRY" },
		{ HIBERNATE5_TYPE_HIBERNATE_NATURAL_ID_KEY, "HIBERNATE5_TYPE_HIBERNATE_NATURAL_ID_KEY" },
		//--------------------------------------------------------------
		// RESERVED FOR JET -300 to -400
		{ JET_SERIALIZER_FIRST, "JET_SERIALIZER_FIRST" },
		{ JET_SERIALIZER_LAST, "JET_SERIALIZER_LAST" },
};

#define HAZELCAST_FRAME_HEADER_LEN    11
#define HEAP_DATA_OVERHEAD 8

static int proto_hazelcast = -1;

static int hf_hazelcast_protocol_header = -1;
static int hf_hazelcast_packet_version = -1;
static int hf_hazelcast_packet_flags = -1;
static int hf_hazelcast_packet_partition_id = -1;
static int hf_hazelcast_packet_payload_size = -1;

static int hf_hazelcast_payload_partition_hash = -1;
static int hf_hazelcast_payload_serializer = -1;
static int hf_hazelcast_payload_data = -1;

static int hf_hazelcast_packet_flag_type0 = -1;
static int hf_hazelcast_packet_flag_op_response = -1;
static int hf_hazelcast_packet_flag_type1 = -1;
static int hf_hazelcast_packet_flag_urgent = -1;
static int hf_hazelcast_packet_flag_type2 = -1;
static int hf_hazelcast_packet_flag_op_control = -1;
static int hf_hazelcast_packet_flag_4_0 = -1;

// DataSerializable & IdentifiedDataSerializable
static int hf_hazelcast_ds_flags = -1;
static int hf_hazelcast_ds_flag_ids = -1;
static int hf_hazelcast_ds_flag_versioned = -1;

// IdentifiedDataSerializable
static int hf_hazelcast_ids_factory_id = -1;
static int hf_hazelcast_ids_class_id = -1;

static int hf_hazelcast_unknown_bytes = -1;

static gint ett_hazelcast = -1;

static gboolean hazelcast_desegment = TRUE;

static int dissect_hazelcast_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static guint get_hazelcast_pdu_len(packet_info *pinfo, tvbuff_t *tvb, int offset, void *data);

static int
dissect_hazelcast(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	guint packet_len = tvb_captured_length(tvb);
	if (packet_len < 3) {
		return 0;
	}

	static gchar *protocol_header = NULL;
	protocol_header = (gchar *)tvb_get_string_enc(wmem_packet_scope(), tvb, 0, 3, ENC_ASCII|ENC_NA);

	if (! strcmp(protocol_header, "HZC")) {
    	protocol_header = (gchar *)tvb_get_string_enc(wmem_packet_scope(), tvb, 0, 3, ENC_ASCII|ENC_NA);
    	col_add_fstr(pinfo->cinfo, COL_INFO, "Header %s", protocol_header);

        proto_item *ti = proto_tree_add_item(tree, proto_hazelcast, tvb, 0, -1, ENC_NA);
        proto_tree *hazelcast_tree = proto_item_add_subtree(ti, ett_hazelcast);

        proto_tree_add_item(hazelcast_tree, hf_hazelcast_protocol_header, tvb, 0, 3, ENC_BIG_ENDIAN);
        return 3;
	}

	tcp_dissect_pdus(tvb, pinfo, tree, hazelcast_desegment, HAZELCAST_FRAME_HEADER_LEN,
		get_hazelcast_pdu_len, dissect_hazelcast_pdu, data);
    return tvb_reported_length(tvb);
}

static guint
get_hazelcast_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
	int payload_size = tvb_get_ntohil(tvb, offset + 7);

    /*
    * That length doesn't include the fixed-length part of the header;
    * add that in.
    */
    return payload_size + HAZELCAST_FRAME_HEADER_LEN;
}

// https://github.com/hazelcast/hazelcast/blob/5.0/hazelcast/src/main/java/com/hazelcast/internal/serialization/impl/DataSerializableSerializer.java#L115-L166
// (private) https://github.com/hazelcast/hazelcast-enterprise/blob/5.0/hazelcast-enterprise/src/main/java/com/hazelcast/internal/serialization/impl/EnterpriseDataSerializableHeader.java
// (private) https://github.com/hazelcast/hazelcast-enterprise/blob/5.0/hazelcast-enterprise/src/main/java/com/hazelcast/internal/serialization/impl/EnterpriseDataSerializableSerializer.java#L130-L137
static int
decode_data_serializable(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = HAZELCAST_FRAME_HEADER_LEN + HEAP_DATA_OVERHEAD;

    static const int * heapdata_flag_fields[] = {
        &hf_hazelcast_ds_flag_ids,
        &hf_hazelcast_ds_flag_versioned,
        NULL
    };

    guint8 header = tvb_get_guint8(tvb, offset);
    gboolean flag_ids = header & FLAG_DATASERIALIZABLE_IDS;
    gboolean flag_versioned = header & FLAG_DATASERIALIZABLE_VERSIONED;

    proto_tree_add_bitmask(tree, tvb, offset, hf_hazelcast_ds_flags, ett_hazelcast, heapdata_flag_fields, ENC_BIG_ENDIAN);
    offset += 1;

    if (flag_ids) {

    }

    // TODO
	return 0;
}

static int
dissect_hazelcast_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
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

	// Member Packet

	// https://github.com/hazelcast/hazelcast/blob/v5.0/hazelcast/src/main/java/com/hazelcast/internal/nio/PacketIOHelper.java#L61-L65

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
	int payload_size;
	proto_tree_add_item_ret_int(hazelcast_tree, hf_hazelcast_packet_payload_size, tvb, offset, 4, ENC_BIG_ENDIAN, &payload_size);
	offset += 4;

	if (payload_size < HEAP_DATA_OVERHEAD) {
		proto_tree_add_item(hazelcast_tree, hf_hazelcast_payload_data, tvb, offset, -1, ENC_BIG_ENDIAN);
		return offset + payload_size;
	}

	// HeapData header
	// https://github.com/hazelcast/hazelcast/blob/v5.0/hazelcast/src/main/java/com/hazelcast/internal/serialization/impl/HeapData.java#L35-L37

	proto_tree_add_item(hazelcast_tree, hf_hazelcast_payload_partition_hash, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	int serializer;
	proto_tree_add_item_ret_int(hazelcast_tree, hf_hazelcast_payload_serializer, tvb, offset, 4, ENC_BIG_ENDIAN, &serializer);
	offset += 4;

	switch (serializer) {
	case CONSTANT_TYPE_DATA_SERIALIZABLE:
		decode_data_serializable(tvb, pinfo, hazelcast_tree);
		break;
	default:
		proto_tree_add_item(hazelcast_tree, hf_hazelcast_payload_data, tvb, offset, -1, ENC_BIG_ENDIAN);
		break;
	}

    return tvb_reported_length(tvb);
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
	    { &hf_hazelcast_payload_partition_hash,
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
	        FT_BYTES, SEP_SPACE,
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
	    },
	    { &hf_hazelcast_ds_flags,
	        { "DataSerializable flags", "hazelcast.dataserializable.flags",
	        FT_UINT8, BASE_DEC,
	        NULL, 0x0,
	        NULL, HFILL }
	    },
	    { &hf_hazelcast_ds_flag_ids,
	        { "Identified Data Serializable", "hazelcast.dataserializable.ids",
	        FT_BOOLEAN, 8,
	        NULL, FLAG_DATASERIALIZABLE_IDS,
	        NULL, HFILL }
	    },
	    { &hf_hazelcast_ds_flag_versioned,
	        { "Versioned (Enterprise)", "hazelcast.dataserializable.versioned",
	        FT_BOOLEAN, 8,
	        NULL, FLAG_DATASERIALIZABLE_VERSIONED,
	        NULL, HFILL }
	    },

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
    static dissector_handle_t hazelcast_handle;

    hazelcast_handle = create_dissector_handle(dissect_hazelcast, proto_hazelcast);
    dissector_add_uint("tcp.port", HAZELCAST_TCP_PORT1, hazelcast_handle);
    dissector_add_uint("tcp.port", HAZELCAST_TCP_PORT2, hazelcast_handle);
    dissector_add_uint("tcp.port", HAZELCAST_TCP_PORT3, hazelcast_handle);
}
