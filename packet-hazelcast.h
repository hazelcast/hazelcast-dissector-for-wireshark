// #define HAZELCAST_MULTICAST_PORT 54327

// https://github.com/hazelcast/hazelcast/blob/v5.0/hazelcast/src/main/java/com/hazelcast/internal/nio/Packet.java#L41-L104

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

// https://github.com/hazelcast/hazelcast/blob/5.0/hazelcast/src/main/java/com/hazelcast/internal/serialization/impl/SerializationConstants.java

#define CONSTANT_TYPE_NULL 0
#define CONSTANT_TYPE_PORTABLE -1
#define CONSTANT_TYPE_DATA_SERIALIZABLE -2
#define CONSTANT_TYPE_BYTE -3
#define CONSTANT_TYPE_BOOLEAN -4
#define CONSTANT_TYPE_CHAR -5
#define CONSTANT_TYPE_SHORT -6
#define CONSTANT_TYPE_INTEGER -7
#define CONSTANT_TYPE_LONG -8
#define CONSTANT_TYPE_FLOAT -9
#define CONSTANT_TYPE_DOUBLE -10
#define CONSTANT_TYPE_STRING -11
#define CONSTANT_TYPE_BYTE_ARRAY -12
#define CONSTANT_TYPE_BOOLEAN_ARRAY -13
#define CONSTANT_TYPE_CHAR_ARRAY -14
#define CONSTANT_TYPE_SHORT_ARRAY -15
#define CONSTANT_TYPE_INTEGER_ARRAY -16
#define CONSTANT_TYPE_LONG_ARRAY -17
#define CONSTANT_TYPE_FLOAT_ARRAY -18
#define CONSTANT_TYPE_DOUBLE_ARRAY -19
#define CONSTANT_TYPE_STRING_ARRAY -20
#define CONSTANT_TYPE_UUID -21
#define CONSTANT_TYPE_SIMPLE_ENTRY -22
#define CONSTANT_TYPE_SIMPLE_IMMUTABLE_ENTRY -23
// ------------------------------------------------------------
// DEFAULT SERIALIZERS
#define JAVA_DEFAULT_TYPE_CLASS -24
#define JAVA_DEFAULT_TYPE_DATE -25
#define JAVA_DEFAULT_TYPE_BIG_INTEGER -26
#define JAVA_DEFAULT_TYPE_BIG_DECIMAL -27
#define JAVA_DEFAULT_TYPE_ARRAY -28
#define JAVA_DEFAULT_TYPE_ARRAY_LIST -29
#define JAVA_DEFAULT_TYPE_LINKED_LIST -30
#define JAVA_DEFAULT_TYPE_COPY_ON_WRITE_ARRAY_LIST -31
#define JAVA_DEFAULT_TYPE_HASH_MAP -32
#define JAVA_DEFAULT_TYPE_CONCURRENT_SKIP_LIST_MAP -33
#define JAVA_DEFAULT_TYPE_CONCURRENT_HASH_MAP -34
#define JAVA_DEFAULT_TYPE_LINKED_HASH_MAP -35
#define JAVA_DEFAULT_TYPE_TREE_MAP -36
#define JAVA_DEFAULT_TYPE_HASH_SET -37
#define JAVA_DEFAULT_TYPE_TREE_SET -38
#define JAVA_DEFAULT_TYPE_LINKED_HASH_SET -39
#define JAVA_DEFAULT_TYPE_COPY_ON_WRITE_ARRAY_SET -40
#define JAVA_DEFAULT_TYPE_CONCURRENT_SKIP_LIST_SET -41
#define JAVA_DEFAULT_TYPE_ARRAY_DEQUE -42
#define JAVA_DEFAULT_TYPE_LINKED_BLOCKING_QUEUE -43
#define JAVA_DEFAULT_TYPE_ARRAY_BLOCKING_QUEUE -44
#define JAVA_DEFAULT_TYPE_PRIORITY_BLOCKING_QUEUE -45
#define JAVA_DEFAULT_TYPE_DELAY_QUEUE -46
#define JAVA_DEFAULT_TYPE_SYNCHRONOUS_QUEUE -47
#define JAVA_DEFAULT_TYPE_LINKED_TRANSFER_QUEUE -48
#define JAVA_DEFAULT_TYPE_PRIORITY_QUEUE -49
#define JAVA_DEFAULT_TYPE_OPTIONAL -50
#define JAVA_DEFAULT_TYPE_LOCALDATE -51
#define JAVA_DEFAULT_TYPE_LOCALTIME -52
#define JAVA_DEFAULT_TYPE_LOCALDATETIME -53
#define JAVA_DEFAULT_TYPE_OFFSETDATETIME -54
#define TYPE_COMPACT -55
#define TYPE_COMPACT_WITH_SCHEMA -56
// ------------------------------------------------------------
// JAVA SERIALIZATION
#define JAVA_DEFAULT_TYPE_SERIALIZABLE -100
#define JAVA_DEFAULT_TYPE_EXTERNALIZABLE -101
// ------------------------------------------------------------
// LANGUAGE SPECIFIC SERIALIZERS
// USED BY CLIENTS (Not deserialized by server)
#define CSHARP_CLR_SERIALIZATION_TYPE -110
#define PYTHON_PICKLE_SERIALIZATION_TYPE -120
#define JAVASCRIPT_JSON_SERIALIZATION_TYPE -130
#define GO_GOB_SERIALIZATION_TYPE -140
// ------------------------------------------------------------
// HIBERNATE SERIALIZERS
#define HIBERNATE3_TYPE_HIBERNATE_CACHE_KEY -200
#define HIBERNATE3_TYPE_HIBERNATE_CACHE_ENTRY -201
#define HIBERNATE4_TYPE_HIBERNATE_CACHE_KEY -202
#define HIBERNATE4_TYPE_HIBERNATE_CACHE_ENTRY -203
#define HIBERNATE5_TYPE_HIBERNATE_CACHE_KEY -204
#define HIBERNATE5_TYPE_HIBERNATE_CACHE_ENTRY -205
#define HIBERNATE5_TYPE_HIBERNATE_NATURAL_ID_KEY -206
//--------------------------------------------------------------
// RESERVED FOR JET -300 to -400
#define JET_SERIALIZER_FIRST -300
#define JET_SERIALIZER_LAST -399

