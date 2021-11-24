#include "config.h"

#include "packet-hazelcast.h"
#include <epan/packet.h>
#include <epan/dissectors/packet-tcp.h>
#include <stdio.h>
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

		{ 0, NULL }
};


// The IdentifiedDataSerializable class names mapping was generated by the following method placed within the
// https://github.com/hazelcast/hazelcast-enterprise/blob/5.0/hazelcast-enterprise/src/test/java/com/hazelcast/internal/serialization/impl/EnterpriseDataSerializableConventionsTest.java
// visibility of private methods in the parent class (DataSerializableConventionsTest) had to be fixed first
//
//   @Test
//   public void listIdsNames() throws Exception {
//       SortedMap<Long, String> classNames = new TreeMap<>();
//
//       Set<Class<? extends IdentifiedDataSerializable>> identifiedDataSerializables = getIDSConcreteClasses();
//       for (Class<? extends IdentifiedDataSerializable> klass : identifiedDataSerializables) {
//           if (!AbstractLocalOperation.class.isAssignableFrom(klass) && !isReadOnlyConfig(klass)) {
//               String className = klass.getName();
//               try {
//                   Constructor<? extends IdentifiedDataSerializable> ctor = klass.getDeclaredConstructor();
//                   ctor.setAccessible(true);
//                   IdentifiedDataSerializable instance = ctor.newInstance();
//                   long factoryId = instance.getFactoryId();
//                   long typeId = instance.getClassId();
//                   long unifiedId = (factoryId << 32) + typeId;
//                   classNames.put(unifiedId, className);
//               } catch (UnsupportedOperationException e) {
//                   System.out.println("Local only: " + className);
//               }
//           }
//       }
//       System.out.println();
//       for (Map.Entry<Long, String> entry: classNames.entrySet()) {
//           System.out.println("{ " +entry.getKey() + ", \"" + entry.getValue() + "\" },");
//       }
//   }

static const val64_string ids_classes[] = {
		{ -4294967291705032704, "com.hazelcast.internal.longregister.operations.AddBackupOperation" },
		{ -4294967291705032703, "com.hazelcast.internal.longregister.operations.AddAndGetOperation" },
		{ -4294967291705032702, "com.hazelcast.internal.longregister.operations.GetOperation" },
		{ -4294967291705032701, "com.hazelcast.internal.longregister.operations.GetAndSetOperation" },
		{ -4294967291705032700, "com.hazelcast.internal.longregister.operations.GetAndAddOperation" },
		{ -4294967291705032699, "com.hazelcast.internal.longregister.operations.SetOperation" },
		{ -4294967291705032698, "com.hazelcast.internal.longregister.operations.SetBackupOperation" },
		{ -4294967291705032697, "com.hazelcast.internal.longregister.operations.LongRegisterReplicationOperation" },
		{ -43379169689599, "com.hazelcast.jet.impl.operation.ExportSnapshotOperation" },
		{ -42984032698368, "com.hazelcast.jet.impl.aggregate.AggregateOpAggregator" },
		{ -42984032698367, "com.hazelcast.jet.impl.aggregate.AggregateOperationImpl" },
		{ -42984032698366, "com.hazelcast.jet.impl.aggregate.AggregateOperation1Impl" },
		{ -42984032698365, "com.hazelcast.jet.impl.aggregate.AggregateOperation2Impl" },
		{ -42984032698364, "com.hazelcast.jet.impl.aggregate.AggregateOperation3Impl" },
		{ -42975442763775, "com.hazelcast.jet.impl.observer.WrappedThrowable" },
		{ -42971147796480, "com.hazelcast.jet.core.metrics.JobMetrics" },
		{ -42971147796479, "com.hazelcast.jet.core.metrics.Measurement" },
		{ -42966852829184, "com.hazelcast.jet.config.JobConfig" },
		{ -42966852829183, "com.hazelcast.jet.config.EdgeConfig" },
		{ -42966852829182, "com.hazelcast.jet.config.ResourceConfig" },
		{ -42962557861887, "com.hazelcast.jet.impl.metrics.RawJobMetrics" },
		{ -42958262894592, "com.hazelcast.jet.impl.execution.init.ExecutionPlan" },
		{ -42958262894591, "com.hazelcast.jet.impl.execution.init.VertexDef" },
		{ -42958262894590, "com.hazelcast.jet.impl.execution.init.EdgeDef" },
		{ -42958262894589, "com.hazelcast.jet.impl.JobRecord" },
		{ -42958262894588, "com.hazelcast.jet.impl.JobResult" },
		{ -42958262894587, "com.hazelcast.jet.impl.operation.InitExecutionOperation" },
		{ -42958262894586, "com.hazelcast.jet.impl.operation.StartExecutionOperation" },
		{ -42958262894584, "com.hazelcast.jet.impl.operation.SubmitJobOperation" },
		{ -42958262894583, "com.hazelcast.jet.impl.operation.GetJobStatusOperation" },
		{ -42958262894582, "com.hazelcast.jet.impl.operation.SnapshotPhase1Operation" },
		{ -42958262894581, "com.hazelcast.jet.impl.JobExecutionRecord" },
		{ -42958262894580, "com.hazelcast.jet.impl.processor.SessionWindowP$Windows" },
		{ -42958262894579, "com.hazelcast.jet.impl.processor.SlidingWindowP$SnapshotKey" },
		{ -42958262894578, "com.hazelcast.jet.impl.operation.GetJobIdsOperation" },
		{ -42958262894577, "com.hazelcast.jet.impl.operation.JoinSubmittedJobOperation" },
		{ -42958262894576, "com.hazelcast.jet.impl.JobRepository$UpdateJobExecutionRecordEntryProcessor" },
		{ -42958262894575, "com.hazelcast.jet.impl.operation.TerminateExecutionOperation" },
		{ -42958262894574, "com.hazelcast.jet.impl.JobRepository$FilterJobResultByNamePredicate" },
		{ -42958262894573, "com.hazelcast.jet.impl.operation.GetJobIdsOperation$GetJobIdsResult" },
		{ -42958262894572, "com.hazelcast.jet.impl.operation.GetJobSubmissionTimeOperation" },
		{ -42958262894571, "com.hazelcast.jet.impl.operation.GetJobConfigOperation" },
		{ -42958262894570, "com.hazelcast.jet.impl.operation.TerminateJobOperation" },
		{ -42958262894569, "com.hazelcast.jet.impl.util.AsyncSnapshotWriterImpl$SnapshotDataKey" },
		{ -42958262894568, "com.hazelcast.jet.impl.util.AsyncSnapshotWriterImpl$SnapshotDataValueTerminator" },
		{ -42958262894567, "com.hazelcast.jet.impl.operation.SnapshotPhase1Operation$SnapshotPhase1Result" },
		{ -42958262894566, "com.hazelcast.jet.impl.operation.ResumeJobOperation" },
		{ -42958262894565, "com.hazelcast.jet.impl.operation.NotifyMemberShutdownOperation" },
		{ -42958262894564, "com.hazelcast.jet.impl.operation.GetJobSummaryListOperation" },
		{ -42958262894563, "com.hazelcast.jet.impl.JobSummary" },
		{ -42958262894562, "com.hazelcast.jet.impl.JobExecutionRecord$SnapshotStats" },
		{ -42958262894561, "com.hazelcast.jet.impl.operation.PrepareForPassiveClusterOperation" },
		{ -42958262894560, "com.hazelcast.jet.impl.SnapshotValidationRecord" },
		{ -42958262894558, "com.hazelcast.jet.impl.operation.GetJobMetricsOperation" },
		{ -42958262894557, "com.hazelcast.jet.impl.operation.GetLocalJobMetricsOperation" },
		{ -42958262894556, "com.hazelcast.jet.impl.operation.SnapshotPhase2Operation" },
		{ -42958262894550, "com.hazelcast.jet.impl.connector.WriteFileP$FileId" },
		{ -42958262894549, "com.hazelcast.jet.impl.JobSuspensionCauseImpl" },
		{ -42958262894548, "com.hazelcast.jet.impl.operation.GetJobSuspensionCauseOperation" },
		{ -42958262894547, "com.hazelcast.jet.impl.processor.ProcessorSupplierFromSimpleSupplier" },
		{ -42958262894546, "com.hazelcast.jet.impl.processor.NoopP$NoopPSupplier" },
		{ -42958262894545, "com.hazelcast.jet.impl.operation.CheckLightJobsOperation" },
		{ -42953967927296, "com.hazelcast.jet.core.DAG" },
		{ -42953967927295, "com.hazelcast.jet.core.Vertex" },
		{ -42953967927294, "com.hazelcast.jet.core.Edge" },
		{ -42953967927293, "com.hazelcast.jet.impl.connector.UpdateMapP$ApplyFnEntryProcessor" },
		{ -42953967927292, "com.hazelcast.jet.impl.connector.AbstractUpdateMapP$ApplyValuesEntryProcessor" },
		{ -4380866641919, "com.hazelcast.cp.event.impl.CPMembershipEventImpl" },
		{ -4380866641918, "com.hazelcast.cp.event.impl.CPGroupAvailabilityEventImpl" },
		{ -4359391805439, "com.hazelcast.cp.internal.datastructures.countdownlatch.CountDownLatchRegistry" },
		{ -4359391805438, "com.hazelcast.cp.internal.datastructures.countdownlatch.CountDownLatch" },
		{ -4359391805437, "com.hazelcast.cp.internal.datastructures.countdownlatch.AwaitInvocationKey" },
		{ -4359391805436, "com.hazelcast.cp.internal.datastructures.countdownlatch.operation.AwaitOp" },
		{ -4359391805435, "com.hazelcast.cp.internal.datastructures.countdownlatch.operation.CountDownOp" },
		{ -4359391805434, "com.hazelcast.cp.internal.datastructures.countdownlatch.operation.GetCountOp" },
		{ -4359391805433, "com.hazelcast.cp.internal.datastructures.countdownlatch.operation.GetRoundOp" },
		{ -4359391805432, "com.hazelcast.cp.internal.datastructures.countdownlatch.operation.TrySetCountOp" },
		{ -4355096838143, "com.hazelcast.cp.internal.datastructures.atomicref.AtomicRefSnapshot" },
		{ -4355096838142, "com.hazelcast.cp.internal.datastructures.atomicref.operation.ApplyOp" },
		{ -4355096838141, "com.hazelcast.cp.internal.datastructures.atomicref.operation.CompareAndSetOp" },
		{ -4355096838140, "com.hazelcast.cp.internal.datastructures.atomicref.operation.ContainsOp" },
		{ -4355096838139, "com.hazelcast.cp.internal.datastructures.atomicref.operation.GetOp" },
		{ -4355096838138, "com.hazelcast.cp.internal.datastructures.atomicref.operation.SetOp" },
		{ -4350801870847, "com.hazelcast.cp.internal.datastructures.semaphore.SemaphoreRegistry" },
		{ -4350801870846, "com.hazelcast.cp.internal.datastructures.semaphore.Semaphore" },
		{ -4350801870845, "com.hazelcast.cp.internal.datastructures.semaphore.AcquireInvocationKey" },
		{ -4350801870844, "com.hazelcast.cp.internal.datastructures.semaphore.SemaphoreEndpoint" },
		{ -4350801870843, "com.hazelcast.cp.internal.datastructures.semaphore.operation.AcquirePermitsOp" },
		{ -4350801870842, "com.hazelcast.cp.internal.datastructures.semaphore.operation.AvailablePermitsOp" },
		{ -4350801870841, "com.hazelcast.cp.internal.datastructures.semaphore.operation.ChangePermitsOp" },
		{ -4350801870840, "com.hazelcast.cp.internal.datastructures.semaphore.operation.DrainPermitsOp" },
		{ -4350801870839, "com.hazelcast.cp.internal.datastructures.semaphore.operation.InitSemaphoreOp" },
		{ -4350801870838, "com.hazelcast.cp.internal.datastructures.semaphore.operation.ReleasePermitsOp" },
		{ -4346506903551, "com.hazelcast.cp.internal.datastructures.lock.LockRegistry" },
		{ -4346506903550, "com.hazelcast.cp.internal.datastructures.lock.Lock" },
		{ -4346506903549, "com.hazelcast.cp.internal.datastructures.lock.LockEndpoint" },
		{ -4346506903548, "com.hazelcast.cp.internal.datastructures.lock.LockInvocationKey" },
		{ -4346506903547, "com.hazelcast.cp.internal.datastructures.lock.LockOwnershipState" },
		{ -4346506903546, "com.hazelcast.cp.internal.datastructures.lock.operation.LockOp" },
		{ -4346506903545, "com.hazelcast.cp.internal.datastructures.lock.operation.TryLockOp" },
		{ -4346506903544, "com.hazelcast.cp.internal.datastructures.lock.operation.UnlockOp" },
		{ -4346506903543, "com.hazelcast.cp.internal.datastructures.lock.operation.GetLockOwnershipStateOp" },
		{ -4342211936255, "com.hazelcast.cp.internal.datastructures.atomiclong.operation.AddAndGetOp" },
		{ -4342211936254, "com.hazelcast.cp.internal.datastructures.atomiclong.operation.CompareAndSetOp" },
		{ -4342211936253, "com.hazelcast.cp.internal.datastructures.atomiclong.operation.GetAndAddOp" },
		{ -4342211936252, "com.hazelcast.cp.internal.datastructures.atomiclong.operation.GetAndSetOp" },
		{ -4342211936251, "com.hazelcast.cp.internal.datastructures.atomiclong.operation.AlterOp" },
		{ -4342211936250, "com.hazelcast.cp.internal.datastructures.atomiclong.operation.ApplyOp" },
		{ -4342211936249, "com.hazelcast.cp.internal.datastructures.atomiclong.operation.LocalGetOp" },
		{ -4342211936248, "com.hazelcast.cp.internal.datastructures.atomiclong.AtomicLongSnapshot" },
		{ -4337916968959, "com.hazelcast.cp.internal.datastructures.spi.blocking.WaitKeyContainer" },
		{ -4337916968958, "com.hazelcast.cp.internal.datastructures.spi.blocking.operation.ExpireWaitKeysOp" },
		{ -4337916968957, "com.hazelcast.cp.internal.datastructures.spi.operation.DestroyRaftObjectOp" },
		{ -4333622001663, "com.hazelcast.cp.internal.persistence.raftop.VerifyRestartedCPMemberOp" },
		{ -4333622001662, "com.hazelcast.cp.internal.persistence.operation.PublishLocalCPMemberOp" },
		{ -4333622001661, "com.hazelcast.cp.internal.persistence.operation.PublishRestoredCPMembersOp" },
		{ -4307852197887, "com.hazelcast.cp.internal.session.CPSessionInfo" },
		{ -4307852197886, "com.hazelcast.cp.internal.session.RaftSessionRegistry" },
		{ -4307852197885, "com.hazelcast.cp.internal.session.SessionResponse" },
		{ -4307852197884, "com.hazelcast.cp.internal.session.operation.CreateSessionOp" },
		{ -4307852197883, "com.hazelcast.cp.internal.session.operation.HeartbeatSessionOp" },
		{ -4307852197882, "com.hazelcast.cp.internal.session.operation.CloseSessionOp" },
		{ -4307852197881, "com.hazelcast.cp.internal.session.operation.ExpireSessionsOp" },
		{ -4307852197880, "com.hazelcast.cp.internal.session.operation.CloseInactiveSessionsOp" },
		{ -4307852197879, "com.hazelcast.cp.internal.session.operation.GetSessionsOp" },
		{ -4307852197878, "com.hazelcast.cp.internal.session.operation.GenerateThreadIdOp" },
		{ -4303557230591, "com.hazelcast.cp.internal.RaftGroupId" },
		{ -4303557230590, "com.hazelcast.cp.internal.CPGroupInfo" },
		{ -4303557230589, "com.hazelcast.cp.internal.operation.integration.PreVoteRequestOp" },
		{ -4303557230588, "com.hazelcast.cp.internal.operation.integration.PreVoteResponseOp" },
		{ -4303557230587, "com.hazelcast.cp.internal.operation.integration.VoteRequestOp" },
		{ -4303557230586, "com.hazelcast.cp.internal.operation.integration.VoteResponseOp" },
		{ -4303557230585, "com.hazelcast.cp.internal.operation.integration.AppendRequestOp" },
		{ -4303557230584, "com.hazelcast.cp.internal.operation.integration.AppendSuccessResponseOp" },
		{ -4303557230583, "com.hazelcast.cp.internal.operation.integration.AppendFailureResponseOp" },
		{ -4303557230582, "com.hazelcast.cp.internal.MetadataRaftGroupSnapshot" },
		{ -4303557230581, "com.hazelcast.cp.internal.operation.integration.InstallSnapshotOp" },
		{ -4303557230580, "com.hazelcast.cp.internal.operation.DefaultRaftReplicateOp" },
		{ -4303557230579, "com.hazelcast.cp.internal.raftop.metadata.CreateRaftGroupOp" },
		{ -4303557230578, "com.hazelcast.cp.internal.raftop.metadata.TriggerDestroyRaftGroupOp" },
		{ -4303557230577, "com.hazelcast.cp.internal.raftop.metadata.CompleteDestroyRaftGroupsOp" },
		{ -4303557230576, "com.hazelcast.cp.internal.raftop.metadata.RemoveCPMemberOp" },
		{ -4303557230575, "com.hazelcast.cp.internal.raftop.metadata.CompleteRaftGroupMembershipChangesOp" },
		{ -4303557230574, "com.hazelcast.cp.internal.operation.ChangeRaftGroupMembershipOp" },
		{ -4303557230573, "com.hazelcast.cp.internal.MembershipChangeSchedule" },
		{ -4303557230572, "com.hazelcast.cp.internal.operation.RaftQueryOp" },
		{ -4303557230571, "com.hazelcast.cp.internal.raftop.metadata.TerminateRaftNodesOp" },
		{ -4303557230570, "com.hazelcast.cp.internal.raftop.metadata.GetActiveCPMembersOp" },
		{ -4303557230569, "com.hazelcast.cp.internal.raftop.metadata.GetDestroyingRaftGroupIdsOp" },
		{ -4303557230568, "com.hazelcast.cp.internal.raftop.metadata.GetMembershipChangeScheduleOp" },
		{ -4303557230567, "com.hazelcast.cp.internal.raftop.metadata.GetRaftGroupOp" },
		{ -4303557230566, "com.hazelcast.cp.internal.raftop.metadata.GetActiveRaftGroupByNameOp" },
		{ -4303557230565, "com.hazelcast.cp.internal.raftop.metadata.CreateRaftNodeOp" },
		{ -4303557230564, "com.hazelcast.cp.internal.operation.DestroyRaftGroupOp" },
		{ -4303557230563, "com.hazelcast.cp.internal.raftop.snapshot.RestoreSnapshotOp" },
		{ -4303557230562, "com.hazelcast.cp.internal.raftop.NotifyTermChangeOp" },
		{ -4303557230561, "com.hazelcast.cp.internal.CPMemberInfo" },
		{ -4303557230560, "com.hazelcast.cp.internal.raftop.metadata.PublishActiveCPMembersOp" },
		{ -4303557230559, "com.hazelcast.cp.internal.raftop.metadata.AddCPMemberOp" },
		{ -4303557230558, "com.hazelcast.cp.internal.raftop.metadata.InitMetadataRaftGroupOp" },
		{ -4303557230557, "com.hazelcast.cp.internal.raftop.metadata.ForceDestroyRaftGroupOp" },
		{ -4303557230556, "com.hazelcast.cp.internal.raftop.GetInitialRaftGroupMembersIfCurrentGroupMemberOp" },
		{ -4303557230555, "com.hazelcast.cp.internal.raftop.metadata.GetRaftGroupIdsOp" },
		{ -4303557230554, "com.hazelcast.cp.internal.raftop.metadata.GetActiveRaftGroupIdsOp" },
		{ -4303557230553, "com.hazelcast.cp.internal.raftop.metadata.RaftServicePreJoinOp" },
		{ -4303557230552, "com.hazelcast.cp.internal.operation.ResetCPMemberOp" },
		{ -4303557230551, "com.hazelcast.cp.internal.MembershipChangeSchedule$CPGroupMembershipChange" },
		{ -4303557230550, "com.hazelcast.cp.internal.operation.unsafe.UnsafeRaftReplicateOp" },
		{ -4303557230549, "com.hazelcast.cp.internal.operation.unsafe.UnsafeRaftQueryOp" },
		{ -4303557230548, "com.hazelcast.cp.internal.operation.unsafe.UnsafeRaftBackupOp" },
		{ -4303557230547, "com.hazelcast.cp.internal.operation.unsafe.UnsafeSnapshotReplicationOp" },
		{ -4303557230546, "com.hazelcast.cp.internal.RaftEndpointImpl" },
		{ -4303557230545, "com.hazelcast.cp.internal.CPGroupSummary" },
		{ -4303557230544, "com.hazelcast.cp.internal.operation.GetLeadedGroupsOp" },
		{ -4303557230543, "com.hazelcast.cp.internal.operation.TransferLeadershipOp" },
		{ -4303557230542, "com.hazelcast.cp.internal.operation.integration.TriggerLeaderElectionOp" },
		{ -4303557230541, "com.hazelcast.cp.internal.UnsafeModePartitionState" },
		{ -4303557230540, "com.hazelcast.cp.internal.operation.unsafe.UnsafeStateReplicationOp" },
		{ -4299262263295, "com.hazelcast.cp.internal.raft.impl.dto.PreVoteRequest" },
		{ -4299262263294, "com.hazelcast.cp.internal.raft.impl.dto.PreVoteResponse" },
		{ -4299262263293, "com.hazelcast.cp.internal.raft.impl.dto.VoteRequest" },
		{ -4299262263292, "com.hazelcast.cp.internal.raft.impl.dto.VoteResponse" },
		{ -4299262263291, "com.hazelcast.cp.internal.raft.impl.dto.AppendRequest" },
		{ -4299262263290, "com.hazelcast.cp.internal.raft.impl.dto.AppendSuccessResponse" },
		{ -4299262263289, "com.hazelcast.cp.internal.raft.impl.dto.AppendFailureResponse" },
		{ -4299262263288, "com.hazelcast.cp.internal.raft.impl.log.LogEntry" },
		{ -4299262263287, "com.hazelcast.cp.internal.raft.impl.log.SnapshotEntry" },
		{ -4299262263286, "com.hazelcast.cp.internal.raft.impl.dto.InstallSnapshot" },
		{ -4299262263285, "com.hazelcast.cp.internal.raft.command.DestroyRaftGroupCmd" },
		{ -4299262263284, "com.hazelcast.cp.internal.raft.impl.command.UpdateRaftGroupMembersCmd" },
		{ -4299262263283, "com.hazelcast.cp.internal.raft.impl.dto.TriggerLeaderElection" },
		{ -184683593727, "com.hazelcast.internal.partition.impl.MerkleTreePartitionComparisonOperation" },
		{ -184683593726, "com.hazelcast.internal.partition.impl.MerkleTreeComparisonResponse" },
		{ -180388626431, "com.hazelcast.internal.serialization.impl.compact.Schema" },
		{ -180388626430, "com.hazelcast.internal.serialization.impl.compact.schema.SendSchemaOperation" },
		{ -180388626429, "com.hazelcast.internal.serialization.impl.compact.schema.FetchSchemaOperation" },
		{ -180388626428, "com.hazelcast.internal.serialization.impl.compact.schema.SendAllSchemasOperation" },
		{ -176093659136, "com.hazelcast.jet.sql.impl.expression.json.JsonQueryFunction" },
		{ -176093659135, "com.hazelcast.jet.sql.impl.expression.json.JsonParseFunction" },
		{ -176093659134, "com.hazelcast.jet.sql.impl.expression.json.JsonValueFunction" },
		{ -171798691839, "com.hazelcast.internal.util.collection.PartitionIdSet" },
		{ -171798691838, "com.hazelcast.internal.util.collection.ImmutablePartitionIdSet" },
		{ -167503724544, "com.hazelcast.json.internal.JsonSchemaNameValue" },
		{ -167503724543, "com.hazelcast.json.internal.JsonSchemaTerminalNode" },
		{ -167503724542, "com.hazelcast.json.internal.JsonSchemaStructNode" },
		{ -163208757248, "com.hazelcast.sql.impl.type.QueryDataType" },
		{ -163208757247, "com.hazelcast.sql.impl.QueryId" },
		{ -163208757246, "com.hazelcast.sql.impl.row.HeapRow" },
		{ -163208757245, "com.hazelcast.sql.impl.row.EmptyRow" },
		{ -163208757244, "com.hazelcast.sql.impl.LazyTarget" },
		{ -163208757243, "com.hazelcast.sql.impl.exec.scan.index.IndexFilterValue" },
		{ -163208757242, "com.hazelcast.sql.impl.exec.scan.index.IndexEqualsFilter" },
		{ -163208757241, "com.hazelcast.sql.impl.exec.scan.index.IndexRangeFilter" },
		{ -163208757240, "com.hazelcast.sql.impl.exec.scan.index.IndexInFilter" },
		{ -163208757239, "com.hazelcast.sql.impl.exec.scan.MapIndexScanMetadata" },
		{ -163208757238, "com.hazelcast.sql.impl.expression.ColumnExpression" },
		{ -163208757237, "com.hazelcast.sql.impl.expression.predicate.IsNullPredicate" },
		{ -163208757236, "com.hazelcast.sql.impl.extract.GenericQueryTargetDescriptor" },
		{ -163208757235, "com.hazelcast.sql.impl.extract.QueryPath" },
		{ -163208757234, "com.hazelcast.sql.impl.expression.ConstantExpression" },
		{ -163208757233, "com.hazelcast.sql.impl.expression.ParameterExpression" },
		{ -163208757232, "com.hazelcast.sql.impl.expression.CastExpression" },
		{ -163208757231, "com.hazelcast.sql.impl.expression.math.DivideFunction" },
		{ -163208757230, "com.hazelcast.sql.impl.expression.math.MinusFunction" },
		{ -163208757229, "com.hazelcast.sql.impl.expression.math.MultiplyFunction" },
		{ -163208757228, "com.hazelcast.sql.impl.expression.math.PlusFunction" },
		{ -163208757227, "com.hazelcast.sql.impl.expression.math.UnaryMinusFunction" },
		{ -163208757226, "com.hazelcast.sql.impl.expression.predicate.AndPredicate" },
		{ -163208757225, "com.hazelcast.sql.impl.expression.predicate.OrPredicate" },
		{ -163208757224, "com.hazelcast.sql.impl.expression.predicate.NotPredicate" },
		{ -163208757223, "com.hazelcast.sql.impl.expression.predicate.ComparisonPredicate" },
		{ -163208757222, "com.hazelcast.sql.impl.expression.predicate.IsTruePredicate" },
		{ -163208757221, "com.hazelcast.sql.impl.expression.predicate.IsNotTruePredicate" },
		{ -163208757220, "com.hazelcast.sql.impl.expression.predicate.IsFalsePredicate" },
		{ -163208757219, "com.hazelcast.sql.impl.expression.predicate.IsNotFalsePredicate" },
		{ -163208757218, "com.hazelcast.sql.impl.expression.predicate.IsNotNullPredicate" },
		{ -163208757217, "com.hazelcast.sql.impl.expression.math.AbsFunction" },
		{ -163208757216, "com.hazelcast.sql.impl.expression.math.SignFunction" },
		{ -163208757215, "com.hazelcast.sql.impl.expression.math.RandFunction" },
		{ -163208757214, "com.hazelcast.sql.impl.expression.math.DoubleFunction" },
		{ -163208757213, "com.hazelcast.sql.impl.expression.math.FloorCeilFunction" },
		{ -163208757212, "com.hazelcast.sql.impl.expression.math.RoundTruncateFunction" },
		{ -163208757211, "com.hazelcast.sql.impl.type.SqlYearMonthInterval" },
		{ -163208757210, "com.hazelcast.sql.impl.type.SqlDaySecondInterval" },
		{ -163208757209, "com.hazelcast.sql.impl.expression.string.AsciiFunction" },
		{ -163208757208, "com.hazelcast.sql.impl.expression.string.CharLengthFunction" },
		{ -163208757207, "com.hazelcast.sql.impl.expression.string.InitcapFunction" },
		{ -163208757206, "com.hazelcast.sql.impl.expression.string.LowerFunction" },
		{ -163208757205, "com.hazelcast.sql.impl.expression.string.UpperFunction" },
		{ -163208757204, "com.hazelcast.sql.impl.expression.string.ConcatFunction" },
		{ -163208757203, "com.hazelcast.sql.impl.expression.string.LikeFunction" },
		{ -163208757202, "com.hazelcast.sql.impl.expression.string.SubstringFunction" },
		{ -163208757201, "com.hazelcast.sql.impl.expression.string.TrimFunction" },
		{ -163208757200, "com.hazelcast.sql.impl.expression.math.RemainderFunction" },
		{ -163208757199, "com.hazelcast.sql.impl.expression.string.ConcatWSFunction" },
		{ -163208757198, "com.hazelcast.sql.impl.expression.string.ReplaceFunction" },
		{ -163208757197, "com.hazelcast.sql.impl.expression.string.PositionFunction" },
		{ -163208757196, "com.hazelcast.sql.impl.expression.CaseExpression" },
		{ -163208757195, "com.hazelcast.sql.impl.expression.datetime.ExtractFunction" },
		{ -163208757194, "com.hazelcast.sql.impl.expression.math.DoubleBiFunction" },
		{ -163208757193, "com.hazelcast.sql.impl.expression.datetime.ToTimestampTzFunction" },
		{ -163208757192, "com.hazelcast.sql.impl.expression.datetime.ToEpochMillisFunction" },
		{ -163208757191, "com.hazelcast.sql.impl.schema.Mapping" },
		{ -163208757190, "com.hazelcast.sql.impl.schema.MappingField" },
		{ -163208757189, "com.hazelcast.sql.impl.expression.SearchableExpression" },
		{ -163208757188, "com.hazelcast.sql.impl.expression.predicate.SearchPredicate" },
		{ -163208757187, "com.hazelcast.sql.impl.schema.view.View" },
		{ -158913789951, "com.hazelcast.internal.metrics.managementcenter.ReadMetricsOperation" },
		{ -154618822655, "com.hazelcast.internal.crdt.pncounter.PNCounterReplicationOperation" },
		{ -154618822654, "com.hazelcast.internal.crdt.pncounter.PNCounterImpl" },
		{ -154618822653, "com.hazelcast.internal.crdt.pncounter.operations.AddOperation" },
		{ -154618822652, "com.hazelcast.internal.crdt.pncounter.operations.GetOperation" },
		{ -154618822651, "com.hazelcast.internal.crdt.pncounter.operations.CRDTTimestampedLong" },
		{ -150323855360, "com.hazelcast.spi.impl.merge.CollectionMergingValueImpl" },
		{ -150323855359, "com.hazelcast.spi.impl.merge.QueueMergingValueImpl" },
		{ -150323855358, "com.hazelcast.spi.impl.merge.AtomicLongMergingValueImpl" },
		{ -150323855357, "com.hazelcast.spi.impl.merge.AtomicReferenceMergingValueImpl" },
		{ -150323855356, "com.hazelcast.spi.impl.merge.MapMergingEntryImpl" },
		{ -150323855355, "com.hazelcast.spi.impl.merge.CacheMergingEntryImpl" },
		{ -150323855354, "com.hazelcast.spi.impl.merge.MultiMapMergingEntryImpl" },
		{ -150323855353, "com.hazelcast.spi.impl.merge.ReplicatedMapMergingEntryImpl" },
		{ -150323855352, "com.hazelcast.spi.impl.merge.RingbufferMergingValueImpl" },
		{ -150323855351, "com.hazelcast.spi.impl.merge.CardinalityEstimatorMergingEntry" },
		{ -150323855350, "com.hazelcast.spi.impl.merge.ScheduledExecutorMergingEntryImpl" },
		{ -150323855349, "com.hazelcast.spi.merge.DiscardMergePolicy" },
		{ -150323855348, "com.hazelcast.spi.merge.ExpirationTimeMergePolicy" },
		{ -150323855347, "com.hazelcast.spi.merge.HigherHitsMergePolicy" },
		{ -150323855346, "com.hazelcast.spi.merge.HyperLogLogMergePolicy" },
		{ -150323855345, "com.hazelcast.spi.merge.LatestAccessMergePolicy" },
		{ -150323855344, "com.hazelcast.spi.merge.LatestUpdateMergePolicy" },
		{ -150323855343, "com.hazelcast.spi.merge.PassThroughMergePolicy" },
		{ -150323855342, "com.hazelcast.spi.merge.PutIfAbsentMergePolicy" },
		{ -146028888064, "com.hazelcast.flakeidgen.impl.NewIdBatchOperation" },
		{ -141733920767, "com.hazelcast.internal.journal.EventJournalInitialSubscriberState" },
		{ -141733920766, "com.hazelcast.internal.journal.DeserializingEntry" },
		{ -137438953472, "com.hazelcast.security.impl.SecureCallableImpl" },
		{ -137438953471, "com.hazelcast.security.ClusterIdentityPrincipal" },
		{ -137438953470, "com.hazelcast.security.ClusterRolePrincipal" },
		{ -137438953469, "com.hazelcast.security.ClusterEndpointPrincipal" },
		{ -133143986176, "com.hazelcast.config.WanReplicationConfig" },
		{ -133143986175, "com.hazelcast.config.WanCustomPublisherConfig" },
		{ -133143986174, "com.hazelcast.config.WanBatchPublisherConfig" },
		{ -133143986173, "com.hazelcast.config.WanConsumerConfig" },
		{ -133143986172, "com.hazelcast.config.NearCacheConfig" },
		{ -133143986171, "com.hazelcast.config.NearCachePreloaderConfig" },
		{ -133143986170, "com.hazelcast.internal.dynamicconfig.AddDynamicConfigOperation" },
		{ -133143986169, "com.hazelcast.internal.dynamicconfig.DynamicConfigPreJoinOperation" },
		{ -133143986168, "com.hazelcast.config.MultiMapConfig" },
		{ -133143986167, "com.hazelcast.config.ListenerConfig" },
		{ -133143986166, "com.hazelcast.config.EntryListenerConfig" },
		{ -133143986165, "com.hazelcast.config.MapConfig" },
		{ -133143986161, "com.hazelcast.config.MapStoreConfig" },
		{ -133143986160, "com.hazelcast.config.MapPartitionLostListenerConfig" },
		{ -133143986159, "com.hazelcast.config.IndexConfig" },
		{ -133143986158, "com.hazelcast.config.AttributeConfig" },
		{ -133143986157, "com.hazelcast.config.QueryCacheConfig" },
		{ -133143986156, "com.hazelcast.config.PredicateConfig" },
		{ -133143986155, "com.hazelcast.config.PartitioningStrategyConfig" },
		{ -133143986154, "com.hazelcast.config.HotRestartConfig" },
		{ -133143986153, "com.hazelcast.config.TopicConfig" },
		{ -133143986152, "com.hazelcast.config.ReliableTopicConfig" },
		{ -133143986151, "com.hazelcast.config.ItemListenerConfig" },
		{ -133143986150, "com.hazelcast.config.QueueStoreConfig" },
		{ -133143986149, "com.hazelcast.config.QueueConfig" },
		{ -133143986148, "com.hazelcast.config.ListConfig" },
		{ -133143986147, "com.hazelcast.config.SetConfig" },
		{ -133143986146, "com.hazelcast.config.ExecutorConfig" },
		{ -133143986145, "com.hazelcast.config.DurableExecutorConfig" },
		{ -133143986144, "com.hazelcast.config.ScheduledExecutorConfig" },
		{ -133143986143, "com.hazelcast.config.ReplicatedMapConfig" },
		{ -133143986142, "com.hazelcast.config.RingbufferConfig" },
		{ -133143986141, "com.hazelcast.config.RingbufferStoreConfig" },
		{ -133143986140, "com.hazelcast.config.CardinalityEstimatorConfig" },
		{ -133143986139, "com.hazelcast.config.CacheSimpleConfig" },
		{ -133143986138, "com.hazelcast.config.CacheSimpleConfig$ExpiryPolicyFactoryConfig" },
		{ -133143986137, "com.hazelcast.config.CacheSimpleConfig$ExpiryPolicyFactoryConfig$TimedExpiryPolicyFactoryConfig" },
		{ -133143986136, "com.hazelcast.config.CacheSimpleConfig$ExpiryPolicyFactoryConfig$DurationConfig" },
		{ -133143986135, "com.hazelcast.config.SplitBrainProtectionConfig" },
		{ -133143986133, "com.hazelcast.config.EventJournalConfig" },
		{ -133143986132, "com.hazelcast.config.SplitBrainProtectionListenerConfig" },
		{ -133143986131, "com.hazelcast.config.CachePartitionLostListenerConfig" },
		{ -133143986130, "com.hazelcast.config.CacheSimpleEntryListenerConfig" },
		{ -133143986129, "com.hazelcast.config.FlakeIdGeneratorConfig" },
		{ -133143986128, "com.hazelcast.config.MergePolicyConfig" },
		{ -133143986127, "com.hazelcast.config.PNCounterConfig" },
		{ -133143986126, "com.hazelcast.config.MerkleTreeConfig" },
		{ -133143986125, "com.hazelcast.config.WanSyncConfig" },
		{ -133143986124, "com.hazelcast.config.KubernetesConfig" },
		{ -133143986123, "com.hazelcast.config.EurekaConfig" },
		{ -133143986122, "com.hazelcast.config.GcpConfig" },
		{ -133143986121, "com.hazelcast.config.AzureConfig" },
		{ -133143986120, "com.hazelcast.config.AwsConfig" },
		{ -133143986119, "com.hazelcast.config.DiscoveryConfig" },
		{ -133143986118, "com.hazelcast.config.DiscoveryStrategyConfig" },
		{ -133143986117, "com.hazelcast.config.WanReplicationRef" },
		{ -133143986116, "com.hazelcast.config.EvictionConfig" },
		{ -133143986115, "com.hazelcast.config.PermissionConfig" },
		{ -133143986114, "com.hazelcast.config.BitmapIndexOptions" },
		{ -133143986113, "com.hazelcast.config.DataPersistenceConfig" },
		{ -128849018880, "com.hazelcast.projection.impl.SingleAttributeProjection" },
		{ -128849018879, "com.hazelcast.projection.impl.MultiAttributeProjection" },
		{ -128849018878, "com.hazelcast.projection.impl.IdentityProjection" },
		{ -124554051584, "com.hazelcast.aggregation.impl.BigDecimalAverageAggregator" },
		{ -124554051583, "com.hazelcast.aggregation.impl.BigDecimalSumAggregator" },
		{ -124554051582, "com.hazelcast.aggregation.impl.BigIntegerAverageAggregator" },
		{ -124554051581, "com.hazelcast.aggregation.impl.BigIntegerSumAggregator" },
		{ -124554051580, "com.hazelcast.aggregation.impl.CountAggregator" },
		{ -124554051579, "com.hazelcast.aggregation.impl.DistinctValuesAggregator" },
		{ -124554051578, "com.hazelcast.aggregation.impl.DoubleAverageAggregator" },
		{ -124554051577, "com.hazelcast.aggregation.impl.DoubleSumAggregator" },
		{ -124554051576, "com.hazelcast.aggregation.impl.FixedSumAggregator" },
		{ -124554051575, "com.hazelcast.aggregation.impl.FloatingPointSumAggregator" },
		{ -124554051574, "com.hazelcast.aggregation.impl.IntegerAverageAggregator" },
		{ -124554051573, "com.hazelcast.aggregation.impl.IntegerSumAggregator" },
		{ -124554051572, "com.hazelcast.aggregation.impl.LongAverageAggregator" },
		{ -124554051571, "com.hazelcast.aggregation.impl.LongSumAggregator" },
		{ -124554051570, "com.hazelcast.aggregation.impl.MaxAggregator" },
		{ -124554051569, "com.hazelcast.aggregation.impl.MinAggregator" },
		{ -124554051568, "com.hazelcast.aggregation.impl.NumberAverageAggregator" },
		{ -124554051567, "com.hazelcast.aggregation.impl.MaxByAggregator" },
		{ -124554051566, "com.hazelcast.aggregation.impl.MinByAggregator" },
		{ -124554051565, "com.hazelcast.aggregation.impl.CanonicalizingHashSet" },
		{ -120259084288, "com.hazelcast.internal.usercodedeployment.impl.ClassData" },
		{ -120259084287, "com.hazelcast.internal.usercodedeployment.impl.operation.ClassDataFinderOperation" },
		{ -120259084286, "com.hazelcast.internal.usercodedeployment.impl.operation.DeployClassesOperation" },
		{ -115964116991, "com.hazelcast.scheduledexecutor.impl.ScheduledTaskHandlerImpl" },
		{ -115964116990, "com.hazelcast.scheduledexecutor.impl.ScheduledTaskDescriptor" },
		{ -115964116989, "com.hazelcast.scheduledexecutor.impl.TaskDefinition" },
		{ -115964116988, "com.hazelcast.scheduledexecutor.impl.ScheduledRunnableAdapter" },
		{ -115964116987, "com.hazelcast.scheduledexecutor.impl.NamedTaskDecorator" },
		{ -115964116986, "com.hazelcast.scheduledexecutor.impl.operations.ScheduleTaskOperation" },
		{ -115964116985, "com.hazelcast.scheduledexecutor.impl.operations.ScheduleTaskBackupOperation" },
		{ -115964116984, "com.hazelcast.scheduledexecutor.impl.operations.CancelTaskOperation" },
		{ -115964116983, "com.hazelcast.scheduledexecutor.impl.operations.CancelTaskBackupOperation" },
		{ -115964116982, "com.hazelcast.scheduledexecutor.impl.operations.GetResultOperation" },
		{ -115964116981, "com.hazelcast.scheduledexecutor.impl.operations.ResultReadyNotifyOperation" },
		{ -115964116980, "com.hazelcast.scheduledexecutor.impl.operations.GetDelayOperation" },
		{ -115964116979, "com.hazelcast.scheduledexecutor.impl.operations.IsDoneOperation" },
		{ -115964116978, "com.hazelcast.scheduledexecutor.impl.operations.IsCanceledOperation" },
		{ -115964116977, "com.hazelcast.scheduledexecutor.impl.operations.GetStatisticsOperation" },
		{ -115964116976, "com.hazelcast.scheduledexecutor.impl.ScheduledTaskStatisticsImpl" },
		{ -115964116975, "com.hazelcast.scheduledexecutor.impl.operations.SyncStateOperation" },
		{ -115964116974, "com.hazelcast.scheduledexecutor.impl.operations.SyncBackupStateOperation" },
		{ -115964116973, "com.hazelcast.scheduledexecutor.impl.operations.ReplicationOperation" },
		{ -115964116972, "com.hazelcast.scheduledexecutor.impl.operations.DisposeTaskOperation" },
		{ -115964116971, "com.hazelcast.scheduledexecutor.impl.operations.DisposeBackupTaskOperation" },
		{ -115964116970, "com.hazelcast.scheduledexecutor.impl.operations.GetAllScheduledOnMemberOperation" },
		{ -115964116969, "com.hazelcast.scheduledexecutor.impl.operations.ShutdownOperation" },
		{ -115964116968, "com.hazelcast.scheduledexecutor.impl.ScheduledTaskResult" },
		{ -115964116967, "com.hazelcast.scheduledexecutor.impl.operations.GetAllScheduledOnPartitionOperation" },
		{ -115964116966, "com.hazelcast.scheduledexecutor.impl.operations.GetAllScheduledOnPartitionOperationFactory" },
		{ -115964116965, "com.hazelcast.scheduledexecutor.impl.operations.MergeOperation" },
		{ -115964116964, "com.hazelcast.scheduledexecutor.impl.operations.MergeBackupOperation" },
		{ -115964116963, "com.hazelcast.scheduledexecutor.impl.HashMapAdapter" },
		{ -115964116962, "com.hazelcast.scheduledexecutor.impl.AutoDisposableTaskDecorator" },
		{ -111669149696, "com.hazelcast.internal.hotrestart.backup.HotRestartBackupTransactionLogRecord" },
		{ -111669149695, "com.hazelcast.internal.hotrestart.backup.HotRestartBackupOperation" },
		{ -111669149694, "com.hazelcast.internal.hotrestart.backup.HotRestartBackupInterruptOperation" },
		{ -107374182400, "com.hazelcast.internal.ascii.memcache.MemcacheEntry" },
		{ -107374182399, "com.hazelcast.internal.ascii.rest.RestValue" },
		{ -103079215103, "com.hazelcast.internal.management.operation.UpdateMapConfigOperation" },
		{ -103079215102, "com.hazelcast.internal.management.operation.SetLicenseOperation" },
		{ -103079215101, "com.hazelcast.internal.management.operation.ChangeClusterStateOperation" },
		{ -103079215100, "com.hazelcast.internal.management.operation.UpdatePermissionConfigOperation" },
		{ -98784247808, "com.hazelcast.internal.hotrestart.cluster.AskForClusterStartResultOperation" },
		{ -98784247807, "com.hazelcast.internal.hotrestart.cluster.AskForExpectedMembersOperation" },
		{ -98784247806, "com.hazelcast.internal.hotrestart.cluster.SendClusterStartResultOperation" },
		{ -98784247805, "com.hazelcast.internal.hotrestart.cluster.SendMemberClusterStartInfoOperation" },
		{ -98784247804, "com.hazelcast.internal.hotrestart.cluster.TriggerForceStartOnMasterOperation" },
		{ -98784247803, "com.hazelcast.internal.hotrestart.cluster.SendExpectedMembersOperation" },
		{ -98784247802, "com.hazelcast.internal.hotrestart.cluster.SendExcludedMemberUuidsOperation" },
		{ -98784247801, "com.hazelcast.internal.hotrestart.cluster.GetClusterStateOperation" },
		{ -94489280512, "com.hazelcast.durableexecutor.impl.operations.DisposeResultBackupOperation" },
		{ -94489280511, "com.hazelcast.durableexecutor.impl.operations.DisposeResultOperation" },
		{ -94489280510, "com.hazelcast.durableexecutor.impl.operations.PutResultOperation" },
		{ -94489280509, "com.hazelcast.durableexecutor.impl.operations.ReplicationOperation" },
		{ -94489280508, "com.hazelcast.durableexecutor.impl.operations.RetrieveAndDisposeResultOperation" },
		{ -94489280507, "com.hazelcast.durableexecutor.impl.operations.RetrieveResultOperation" },
		{ -94489280506, "com.hazelcast.durableexecutor.impl.operations.ShutdownOperation" },
		{ -94489280505, "com.hazelcast.durableexecutor.impl.operations.TaskBackupOperation" },
		{ -94489280504, "com.hazelcast.durableexecutor.impl.operations.TaskOperation" },
		{ -94489280503, "com.hazelcast.durableexecutor.impl.operations.PutResultBackupOperation" },
		{ -90194313216, "com.hazelcast.cardinality.impl.operations.AggregateOperation" },
		{ -90194313215, "com.hazelcast.cardinality.impl.operations.EstimateOperation" },
		{ -90194313214, "com.hazelcast.cardinality.impl.operations.AggregateBackupOperation" },
		{ -90194313213, "com.hazelcast.cardinality.impl.operations.ReplicationOperation" },
		{ -90194313212, "com.hazelcast.cardinality.impl.CardinalityEstimatorContainer" },
		{ -90194313211, "com.hazelcast.cardinality.impl.hyperloglog.impl.HyperLogLogImpl" },
		{ -90194313210, "com.hazelcast.cardinality.impl.hyperloglog.impl.DenseHyperLogLogEncoder" },
		{ -90194313209, "com.hazelcast.cardinality.impl.hyperloglog.impl.SparseHyperLogLogEncoder" },
		{ -90194313208, "com.hazelcast.cardinality.impl.operations.MergeOperation" },
		{ -90194313207, "com.hazelcast.cardinality.impl.operations.MergeBackupOperation" },
		{ -85899345920, "com.hazelcast.query.impl.predicates.SqlPredicate" },
		{ -85899345919, "com.hazelcast.query.impl.predicates.AndPredicate" },
		{ -85899345918, "com.hazelcast.query.impl.predicates.BetweenPredicate" },
		{ -85899345917, "com.hazelcast.query.impl.predicates.EqualPredicate" },
		{ -85899345916, "com.hazelcast.query.impl.predicates.GreaterLessPredicate" },
		{ -85899345915, "com.hazelcast.query.impl.predicates.LikePredicate" },
		{ -85899345914, "com.hazelcast.query.impl.predicates.ILikePredicate" },
		{ -85899345913, "com.hazelcast.query.impl.predicates.InPredicate" },
		{ -85899345912, "com.hazelcast.query.impl.predicates.InstanceOfPredicate" },
		{ -85899345911, "com.hazelcast.query.impl.predicates.NotEqualPredicate" },
		{ -85899345910, "com.hazelcast.query.impl.predicates.NotPredicate" },
		{ -85899345909, "com.hazelcast.query.impl.predicates.OrPredicate" },
		{ -85899345908, "com.hazelcast.query.impl.predicates.RegexPredicate" },
		{ -85899345907, "com.hazelcast.query.impl.predicates.FalsePredicate" },
		{ -85899345906, "com.hazelcast.query.impl.predicates.TruePredicate" },
		{ -85899345905, "com.hazelcast.query.impl.predicates.PagingPredicateImpl" },
		{ -85899345904, "com.hazelcast.query.impl.predicates.PartitionPredicateImpl" },
		{ -85899345903, "com.hazelcast.query.impl.AbstractIndex$NullObject" },
		{ -85899345902, "com.hazelcast.query.impl.CompositeValue" },
		{ -85899345901, "com.hazelcast.query.impl.CompositeValue$NegativeInfinity" },
		{ -85899345900, "com.hazelcast.query.impl.CompositeValue$PositiveInfinity" },
		{ -81604378624, "com.hazelcast.map.impl.wan.WanMapAddOrUpdateEvent" },
		{ -81604378623, "com.hazelcast.map.impl.wan.WanMapRemoveEvent" },
		{ -81604378620, "com.hazelcast.wan.impl.WanEventContainerReplicationOperation" },
		{ -77309411327, "com.hazelcast.map.impl.operation.MerkleTreeNodeCompareOperation" },
		{ -77309411326, "com.hazelcast.map.impl.operation.MerkleTreeNodeCompareOperationFactory" },
		{ -77309411325, "com.hazelcast.map.impl.operation.MerkleTreeGetEntriesOperation" },
		{ -77309411324, "com.hazelcast.map.impl.operation.MerkleTreeGetEntryCountOperation" },
		{ -77309411322, "com.hazelcast.map.impl.operation.EnterpriseMapReplicationOperation" },
		{ -77309411321, "com.hazelcast.map.impl.EnterpriseMapReplicationStateHolder" },
		{ -77309411319, "com.hazelcast.map.impl.operation.MapMerkleTreePartitionCompareOperation" },
		{ -73014444031, "com.hazelcast.ringbuffer.impl.operations.GenericOperation" },
		{ -73014444030, "com.hazelcast.ringbuffer.impl.operations.AddBackupOperation" },
		{ -73014444029, "com.hazelcast.ringbuffer.impl.operations.AddOperation" },
		{ -73014444028, "com.hazelcast.ringbuffer.impl.operations.ReadOneOperation" },
		{ -73014444027, "com.hazelcast.ringbuffer.impl.operations.ReplicationOperation" },
		{ -73014444026, "com.hazelcast.ringbuffer.impl.operations.ReadManyOperation" },
		{ -73014444025, "com.hazelcast.ringbuffer.impl.operations.AddAllOperation" },
		{ -73014444024, "com.hazelcast.ringbuffer.impl.operations.AddAllBackupOperation" },
		{ -73014444023, "com.hazelcast.ringbuffer.impl.ReadResultSetImpl" },
		{ -73014444022, "com.hazelcast.ringbuffer.impl.RingbufferContainer" },
		{ -73014444021, "com.hazelcast.ringbuffer.impl.operations.MergeOperation" },
		{ -73014444020, "com.hazelcast.ringbuffer.impl.operations.MergeBackupOperation" },
		{ -68719476736, "com.hazelcast.enterprise.wan.impl.replication.WanEventBatch" },
		{ -68719476735, "com.hazelcast.enterprise.wan.impl.operation.WanPutOperation" },
		{ -68719476734, "com.hazelcast.enterprise.wan.impl.operation.WanPutBackupOperation" },
		{ -68719476733, "com.hazelcast.enterprise.wan.impl.WanEventMigrationContainer" },
		{ -68719476732, "com.hazelcast.map.impl.wan.WanEnterpriseMapAddOrUpdateEvent" },
		{ -68719476731, "com.hazelcast.map.impl.wan.WanEnterpriseMapRemoveEvent" },
		{ -68719476730, "com.hazelcast.cache.impl.wan.WanEnterpriseCacheAddOrUpdateEvent" },
		{ -68719476729, "com.hazelcast.cache.impl.wan.WanEnterpriseCacheRemoveEvent" },
		{ -68719476728, "com.hazelcast.map.impl.wan.WanEnterpriseMapSyncEvent" },
		{ -68719476727, "com.hazelcast.enterprise.wan.impl.sync.WanAntiEntropyEventPublishOperation" },
		{ -68719476726, "com.hazelcast.enterprise.wan.impl.sync.GetMapPartitionDataOperation" },
		{ -68719476725, "com.hazelcast.enterprise.wan.impl.operation.PostJoinWanOperation" },
		{ -68719476724, "com.hazelcast.enterprise.wan.impl.operation.WanEventContainerOperation" },
		{ -68719476723, "com.hazelcast.enterprise.wan.impl.WanSyncEvent" },
		{ -68719476722, "com.hazelcast.enterprise.wan.impl.sync.WanAntiEntropyEventResult" },
		{ -68719476720, "com.hazelcast.enterprise.wan.impl.WanConsistencyCheckEvent" },
		{ -68719476719, "com.hazelcast.enterprise.wan.impl.operation.WanMerkleTreeNodeCompareOperation" },
		{ -68719476718, "com.hazelcast.enterprise.wan.impl.operation.MerkleTreeNodeValueComparison" },
		{ -68719476717, "com.hazelcast.map.impl.wan.WanEnterpriseMapMerkleTreeNode" },
		{ -68719476716, "com.hazelcast.enterprise.wan.impl.operation.AddWanConfigOperationFactory" },
		{ -68719476715, "com.hazelcast.enterprise.wan.impl.operation.AddWanConfigOperation" },
		{ -68719476714, "com.hazelcast.enterprise.wan.impl.operation.AddWanConfigBackupOperation" },
		{ -68719476713, "com.hazelcast.enterprise.wan.impl.operation.RemoveWanEventBackupsOperation" },
		{ -68719476712, "com.hazelcast.enterprise.wan.impl.operation.WanProtocolNegotiationOperation" },
		{ -68719476711, "com.hazelcast.enterprise.wan.impl.operation.WanProtocolNegotiationResponse" },
		{ -64424509440, "com.hazelcast.cache.impl.operation.WanCacheRemoveOperation" },
		{ -64424509438, "com.hazelcast.cache.impl.operation.WanCacheMergeOperation" },
		{ -64424509437, "com.hazelcast.cache.impl.operation.CacheMerkleTreePartitionCompareOperation" },
		{ -64424509436, "com.hazelcast.cache.impl.operation.EnterpriseCacheReplicationOperation" },
		{ -60129542144, "com.hazelcast.cache.impl.hidensity.operation.CacheGetOperation" },
		{ -60129542143, "com.hazelcast.cache.impl.hidensity.operation.CacheContainsKeyOperation" },
		{ -60129542142, "com.hazelcast.cache.impl.hidensity.operation.CachePutOperation" },
		{ -60129542141, "com.hazelcast.cache.impl.hidensity.operation.CachePutIfAbsentOperation" },
		{ -60129542140, "com.hazelcast.cache.impl.hidensity.operation.CacheRemoveOperation" },
		{ -60129542139, "com.hazelcast.cache.impl.hidensity.operation.CacheGetAndRemoveOperation" },
		{ -60129542138, "com.hazelcast.cache.impl.hidensity.operation.CacheReplaceOperation" },
		{ -60129542137, "com.hazelcast.cache.impl.hidensity.operation.CacheGetAndReplaceOperation" },
		{ -60129542136, "com.hazelcast.cache.impl.hidensity.operation.CachePutBackupOperation" },
		{ -60129542135, "com.hazelcast.cache.impl.hidensity.operation.CachePutAllBackupOperation" },
		{ -60129542134, "com.hazelcast.cache.impl.hidensity.operation.CacheRemoveBackupOperation" },
		{ -60129542133, "com.hazelcast.cache.impl.hidensity.operation.CacheSizeOperation" },
		{ -60129542132, "com.hazelcast.cache.impl.hidensity.operation.CacheSizeOperationFactory" },
		{ -60129542130, "com.hazelcast.cache.impl.hidensity.operation.CacheGetAllOperation" },
		{ -60129542129, "com.hazelcast.cache.impl.hidensity.operation.CacheGetAllOperationFactory" },
		{ -60129542128, "com.hazelcast.cache.impl.hidensity.operation.CacheLoadAllOperation" },
		{ -60129542127, "com.hazelcast.cache.impl.hidensity.operation.CacheLoadAllOperationFactory" },
		{ -60129542126, "com.hazelcast.cache.impl.hidensity.operation.CacheEntryProcessorOperation" },
		{ -60129542125, "com.hazelcast.cache.impl.hidensity.operation.WanCacheRemoveOperation" },
		{ -60129542124, "com.hazelcast.cache.impl.hidensity.operation.CachePutAllOperation" },
		{ -60129542123, "com.hazelcast.cache.impl.hidensity.operation.HiDensityCacheReplicationOperation" },
		{ -60129542121, "com.hazelcast.cache.impl.hidensity.operation.WanCacheMergeOperation" },
		{ -60129542120, "com.hazelcast.cache.impl.hidensity.operation.CacheMergeOperation" },
		{ -60129542119, "com.hazelcast.cache.impl.hidensity.operation.CacheMergeBackupOperation" },
		{ -60129542118, "com.hazelcast.cache.impl.hidensity.operation.CacheMergeOperationFactory" },
		{ -60129542117, "com.hazelcast.cache.impl.hidensity.operation.CacheSetExpiryPolicyOperation" },
		{ -60129542116, "com.hazelcast.cache.impl.hidensity.operation.CacheSetExpiryPolicyBackupOperation" },
		{ -55834574847, "com.hazelcast.cache.impl.operation.CacheGetOperation" },
		{ -55834574846, "com.hazelcast.cache.impl.operation.CacheContainsKeyOperation" },
		{ -55834574845, "com.hazelcast.cache.impl.operation.CachePutOperation" },
		{ -55834574844, "com.hazelcast.cache.impl.operation.CachePutIfAbsentOperation" },
		{ -55834574843, "com.hazelcast.cache.impl.operation.CacheRemoveOperation" },
		{ -55834574842, "com.hazelcast.cache.impl.operation.CacheGetAndRemoveOperation" },
		{ -55834574841, "com.hazelcast.cache.impl.operation.CacheReplaceOperation" },
		{ -55834574840, "com.hazelcast.cache.impl.operation.CacheGetAndReplaceOperation" },
		{ -55834574839, "com.hazelcast.cache.impl.operation.CachePutBackupOperation" },
		{ -55834574838, "com.hazelcast.cache.impl.operation.CachePutAllBackupOperation" },
		{ -55834574837, "com.hazelcast.cache.impl.operation.CacheRemoveBackupOperation" },
		{ -55834574836, "com.hazelcast.cache.impl.operation.CacheClearBackupOperation" },
		{ -55834574835, "com.hazelcast.cache.impl.operation.CacheSizeOperation" },
		{ -55834574834, "com.hazelcast.cache.impl.operation.CacheSizeOperationFactory" },
		{ -55834574833, "com.hazelcast.cache.impl.operation.CacheClearOperation" },
		{ -55834574832, "com.hazelcast.cache.impl.operation.CacheClearOperationFactory" },
		{ -55834574831, "com.hazelcast.cache.impl.operation.CacheGetAllOperation" },
		{ -55834574830, "com.hazelcast.cache.impl.operation.CacheGetAllOperationFactory" },
		{ -55834574829, "com.hazelcast.cache.impl.operation.CacheLoadAllOperation" },
		{ -55834574828, "com.hazelcast.cache.impl.operation.CacheLoadAllOperationFactory" },
		{ -55834574827, "com.hazelcast.cache.HazelcastExpiryPolicy" },
		{ -55834574826, "com.hazelcast.cache.impl.operation.CacheFetchKeysOperation" },
		{ -55834574825, "com.hazelcast.cache.impl.CacheKeysWithCursor" },
		{ -55834574824, "com.hazelcast.cache.impl.operation.CacheEntryProcessorOperation" },
		{ -55834574823, "com.hazelcast.cache.impl.CacheClearResponse" },
		{ -55834574822, "com.hazelcast.cache.impl.operation.CacheGetConfigOperation" },
		{ -55834574821, "com.hazelcast.cache.impl.operation.CacheManagementConfigOperation" },
		{ -55834574820, "com.hazelcast.cache.impl.operation.CacheListenerRegistrationOperation" },
		{ -55834574819, "com.hazelcast.cache.impl.operation.CacheDestroyOperation" },
		{ -55834574818, "com.hazelcast.cache.impl.CacheEventDataImpl" },
		{ -55834574817, "com.hazelcast.cache.impl.CacheEventSet" },
		{ -55834574816, "com.hazelcast.cache.impl.operation.CacheBackupEntryProcessorOperation" },
		{ -55834574815, "com.hazelcast.cache.impl.operation.CacheRemoveAllOperation" },
		{ -55834574814, "com.hazelcast.cache.impl.operation.CacheRemoveAllBackupOperation" },
		{ -55834574813, "com.hazelcast.cache.impl.operation.CacheRemoveAllOperationFactory" },
		{ -55834574812, "com.hazelcast.cache.impl.operation.CachePutAllOperation" },
		{ -55834574811, "com.hazelcast.cache.impl.operation.CacheFetchEntriesOperation" },
		{ -55834574810, "com.hazelcast.cache.impl.CacheEntriesWithCursor" },
		{ -55834574809, "com.hazelcast.cache.impl.event.CachePartitionLostEventFilter" },
		{ -55834574808, "com.hazelcast.cache.impl.merge.entry.DefaultCacheEntryView" },
		{ -55834574807, "com.hazelcast.cache.impl.operation.CacheReplicationOperation" },
		{ -55834574806, "com.hazelcast.cache.impl.operation.OnJoinCacheOperation" },
		{ -55834574805, "com.hazelcast.cache.impl.record.CacheDataRecord" },
		{ -55834574804, "com.hazelcast.cache.impl.record.CacheObjectRecord" },
		{ -55834574803, "com.hazelcast.cache.impl.CachePartitionEventData" },
		{ -55834574802, "com.hazelcast.cache.impl.operation.CacheGetInvalidationMetaDataOperation" },
		{ -55834574801, "com.hazelcast.cache.impl.operation.CacheGetInvalidationMetaDataOperation$MetaDataResponse" },
		{ -55834574800, "com.hazelcast.client.impl.protocol.task.cache.CacheAssignAndGetUuidsOperation" },
		{ -55834574799, "com.hazelcast.client.impl.protocol.task.cache.CacheAssignAndGetUuidsOperationFactory" },
		{ -55834574798, "com.hazelcast.cache.impl.operation.CacheNearCacheStateHolder" },
		{ -55834574797, "com.hazelcast.cache.impl.CacheEventListenerAdaptor" },
		{ -55834574796, "com.hazelcast.cache.impl.journal.CacheEventJournalSubscribeOperation" },
		{ -55834574795, "com.hazelcast.cache.impl.journal.CacheEventJournalReadOperation" },
		{ -55834574794, "com.hazelcast.cache.impl.journal.DeserializingEventJournalCacheEvent" },
		{ -55834574793, "com.hazelcast.cache.impl.journal.InternalEventJournalCacheEvent" },
		{ -55834574792, "com.hazelcast.cache.impl.journal.CacheEventJournalReadResultSetImpl" },
		{ -55834574791, "com.hazelcast.cache.impl.PreJoinCacheConfig" },
		{ -55834574790, "com.hazelcast.internal.management.operation.GetCacheEntryViewEntryProcessor$CacheBrowserEntryView" },
		{ -55834574789, "com.hazelcast.internal.management.operation.GetCacheEntryViewEntryProcessor" },
		{ -55834574788, "com.hazelcast.cache.impl.operation.CacheMergeOperationFactory" },
		{ -55834574787, "com.hazelcast.cache.impl.operation.CacheMergeOperation" },
		{ -55834574786, "com.hazelcast.cache.impl.operation.AddCacheConfigOperation" },
		{ -55834574785, "com.hazelcast.cache.impl.operation.CacheSetExpiryPolicyOperation" },
		{ -55834574784, "com.hazelcast.cache.impl.operation.CacheSetExpiryPolicyBackupOperation" },
		{ -55834574783, "com.hazelcast.cache.impl.operation.CacheExpireBatchBackupOperation" },
		{ -55834574781, "com.hazelcast.config.CacheConfig" },
		{ -51539607551, "com.hazelcast.replicatedmap.impl.operation.ClearOperation" },
		{ -51539607550, "com.hazelcast.replicatedmap.impl.record.ReplicatedMapEntryView" },
		{ -51539607549, "com.hazelcast.replicatedmap.impl.operation.ReplicateUpdateOperation" },
		{ -51539607548, "com.hazelcast.replicatedmap.impl.operation.ReplicateUpdateToCallerOperation" },
		{ -51539607547, "com.hazelcast.replicatedmap.impl.operation.PutAllOperation" },
		{ -51539607546, "com.hazelcast.replicatedmap.impl.operation.PutOperation" },
		{ -51539607545, "com.hazelcast.replicatedmap.impl.operation.RemoveOperation" },
		{ -51539607544, "com.hazelcast.replicatedmap.impl.operation.SizeOperation" },
		{ -51539607543, "com.hazelcast.replicatedmap.impl.operation.VersionResponsePair" },
		{ -51539607542, "com.hazelcast.replicatedmap.impl.operation.GetOperation" },
		{ -51539607541, "com.hazelcast.replicatedmap.impl.operation.CheckReplicaVersionOperation" },
		{ -51539607540, "com.hazelcast.replicatedmap.impl.operation.ContainsKeyOperation" },
		{ -51539607539, "com.hazelcast.replicatedmap.impl.operation.ContainsValueOperation" },
		{ -51539607538, "com.hazelcast.replicatedmap.impl.operation.EntrySetOperation" },
		{ -51539607537, "com.hazelcast.replicatedmap.impl.operation.EvictionOperation" },
		{ -51539607536, "com.hazelcast.replicatedmap.impl.operation.IsEmptyOperation" },
		{ -51539607535, "com.hazelcast.replicatedmap.impl.operation.KeySetOperation" },
		{ -51539607534, "com.hazelcast.replicatedmap.impl.operation.ReplicationOperation" },
		{ -51539607533, "com.hazelcast.replicatedmap.impl.operation.RequestMapDataOperation" },
		{ -51539607532, "com.hazelcast.replicatedmap.impl.operation.SyncReplicatedMapDataOperation" },
		{ -51539607531, "com.hazelcast.replicatedmap.impl.operation.ValuesOperation" },
		{ -51539607530, "com.hazelcast.replicatedmap.impl.operation.ClearOperationFactory" },
		{ -51539607529, "com.hazelcast.replicatedmap.impl.operation.PutAllOperationFactory" },
		{ -51539607528, "com.hazelcast.replicatedmap.impl.record.RecordMigrationInfo" },
		{ -51539607527, "com.hazelcast.replicatedmap.impl.operation.MergeOperationFactory" },
		{ -51539607526, "com.hazelcast.replicatedmap.impl.operation.MergeOperation" },
		{ -47244640255, "com.hazelcast.collection.impl.collection.operations.CollectionAddOperation" },
		{ -47244640254, "com.hazelcast.collection.impl.collection.operations.CollectionAddBackupOperation" },
		{ -47244640253, "com.hazelcast.collection.impl.list.operations.ListAddOperation" },
		{ -47244640252, "com.hazelcast.collection.impl.list.operations.ListGetOperation" },
		{ -47244640251, "com.hazelcast.collection.impl.collection.operations.CollectionRemoveOperation" },
		{ -47244640250, "com.hazelcast.collection.impl.collection.operations.CollectionRemoveBackupOperation" },
		{ -47244640249, "com.hazelcast.collection.impl.collection.operations.CollectionSizeOperation" },
		{ -47244640248, "com.hazelcast.collection.impl.collection.operations.CollectionClearOperation" },
		{ -47244640247, "com.hazelcast.collection.impl.collection.operations.CollectionClearBackupOperation" },
		{ -47244640246, "com.hazelcast.collection.impl.list.operations.ListSetOperation" },
		{ -47244640245, "com.hazelcast.collection.impl.list.operations.ListSetBackupOperation" },
		{ -47244640244, "com.hazelcast.collection.impl.list.operations.ListRemoveOperation" },
		{ -47244640243, "com.hazelcast.collection.impl.list.operations.ListIndexOfOperation" },
		{ -47244640242, "com.hazelcast.collection.impl.collection.operations.CollectionContainsOperation" },
		{ -47244640241, "com.hazelcast.collection.impl.collection.operations.CollectionAddAllOperation" },
		{ -47244640240, "com.hazelcast.collection.impl.collection.operations.CollectionAddAllBackupOperation" },
		{ -47244640239, "com.hazelcast.collection.impl.list.operations.ListAddAllOperation" },
		{ -47244640238, "com.hazelcast.collection.impl.list.operations.ListSubOperation" },
		{ -47244640237, "com.hazelcast.collection.impl.collection.operations.CollectionCompareAndRemoveOperation" },
		{ -47244640236, "com.hazelcast.collection.impl.collection.operations.CollectionGetAllOperation" },
		{ -47244640235, "com.hazelcast.collection.impl.collection.CollectionEventFilter" },
		{ -47244640234, "com.hazelcast.collection.impl.collection.CollectionEvent" },
		{ -47244640233, "com.hazelcast.collection.impl.collection.CollectionItem" },
		{ -47244640232, "com.hazelcast.collection.impl.txncollection.operations.CollectionReserveAddOperation" },
		{ -47244640231, "com.hazelcast.collection.impl.txncollection.operations.CollectionReserveRemoveOperation" },
		{ -47244640230, "com.hazelcast.collection.impl.txncollection.operations.CollectionTxnAddOperation" },
		{ -47244640229, "com.hazelcast.collection.impl.txncollection.operations.CollectionTxnAddBackupOperation" },
		{ -47244640228, "com.hazelcast.collection.impl.txncollection.operations.CollectionTxnRemoveOperation" },
		{ -47244640227, "com.hazelcast.collection.impl.txncollection.operations.CollectionTxnRemoveBackupOperation" },
		{ -47244640226, "com.hazelcast.collection.impl.txncollection.operations.CollectionPrepareOperation" },
		{ -47244640225, "com.hazelcast.collection.impl.txncollection.operations.CollectionPrepareBackupOperation" },
		{ -47244640224, "com.hazelcast.collection.impl.txncollection.operations.CollectionRollbackOperation" },
		{ -47244640223, "com.hazelcast.collection.impl.txncollection.operations.CollectionRollbackBackupOperation" },
		{ -47244640222, "com.hazelcast.collection.impl.collection.TxCollectionItem" },
		{ -47244640221, "com.hazelcast.collection.impl.txncollection.operations.CollectionTransactionRollbackOperation" },
		{ -47244640220, "com.hazelcast.collection.impl.list.operations.ListReplicationOperation" },
		{ -47244640219, "com.hazelcast.collection.impl.set.operations.SetReplicationOperation" },
		{ -47244640218, "com.hazelcast.collection.impl.collection.operations.CollectionIsEmptyOperation" },
		{ -47244640217, "com.hazelcast.collection.impl.txncollection.operations.CollectionCommitOperation" },
		{ -47244640216, "com.hazelcast.collection.impl.txncollection.operations.CollectionCommitBackupOperation" },
		{ -47244640215, "com.hazelcast.collection.impl.set.SetContainer" },
		{ -47244640214, "com.hazelcast.collection.impl.list.ListContainer" },
		{ -47244640213, "com.hazelcast.collection.impl.txncollection.CollectionTransactionLogRecord" },
		{ -47244640212, "com.hazelcast.collection.impl.txnqueue.QueueTransactionLogRecord" },
		{ -47244640211, "com.hazelcast.collection.impl.collection.operations.CollectionMergeOperation" },
		{ -47244640210, "com.hazelcast.collection.impl.collection.operations.CollectionMergeBackupOperation" },
		{ -42949672960, "com.hazelcast.transaction.impl.operations.CreateTxBackupLogOperation" },
		{ -42949672959, "com.hazelcast.transaction.impl.operations.BroadcastTxRollbackOperation" },
		{ -42949672958, "com.hazelcast.transaction.impl.operations.PurgeTxBackupLogOperation" },
		{ -42949672957, "com.hazelcast.transaction.impl.operations.ReplicateTxBackupLogOperation" },
		{ -42949672956, "com.hazelcast.transaction.impl.operations.RollbackTxBackupLogOperation" },
		{ -42949672955, "com.hazelcast.transaction.impl.operations.CreateAllowedDuringPassiveStateTxBackupLogOperation" },
		{ -42949672954, "com.hazelcast.transaction.impl.operations.PurgeAllowedDuringPassiveStateTxBackupLogOperation" },
		{ -42949672953, "com.hazelcast.transaction.impl.operations.ReplicateAllowedDuringPassiveStateTxBackupLogOperation" },
		{ -42949672952, "com.hazelcast.transaction.impl.operations.RollbackAllowedDuringPassiveStateTxBackupLogOperation" },
		{ -42949672951, "com.hazelcast.transaction.impl.xa.operations.ClearRemoteTransactionBackupOperation" },
		{ -42949672950, "com.hazelcast.transaction.impl.xa.operations.ClearRemoteTransactionOperation" },
		{ -42949672949, "com.hazelcast.transaction.impl.xa.operations.CollectRemoteTransactionsOperation" },
		{ -42949672947, "com.hazelcast.transaction.impl.xa.operations.FinalizeRemoteTransactionBackupOperation" },
		{ -42949672946, "com.hazelcast.transaction.impl.xa.operations.FinalizeRemoteTransactionOperation" },
		{ -42949672945, "com.hazelcast.transaction.impl.xa.operations.PutRemoteTransactionBackupOperation" },
		{ -42949672944, "com.hazelcast.transaction.impl.xa.operations.PutRemoteTransactionOperation" },
		{ -42949672943, "com.hazelcast.transaction.impl.xa.operations.XaReplicationOperation" },
		{ -42949672942, "com.hazelcast.transaction.impl.xa.XATransactionDTO" },
		{ -38654705664, "com.hazelcast.topic.impl.PublishOperation" },
		{ -38654705663, "com.hazelcast.topic.impl.TopicEvent" },
		{ -38654705662, "com.hazelcast.topic.impl.reliable.ReliableTopicMessage" },
		{ -38654705661, "com.hazelcast.topic.impl.PublishAllOperation" },
		{ -34359738368, "com.hazelcast.internal.locksupport.LockResourceImpl" },
		{ -34359738367, "com.hazelcast.internal.locksupport.LockStoreImpl" },
		{ -34359738359, "com.hazelcast.internal.locksupport.operations.IsLockedOperation" },
		{ -34359738358, "com.hazelcast.internal.locksupport.operations.LockBackupOperation" },
		{ -34359738357, "com.hazelcast.internal.locksupport.operations.LockOperation" },
		{ -34359738356, "com.hazelcast.internal.locksupport.operations.LockReplicationOperation" },
		{ -34359738353, "com.hazelcast.internal.locksupport.operations.UnlockBackupOperation" },
		{ -34359738352, "com.hazelcast.internal.locksupport.operations.UnlockOperation" },
		{ -34359738351, "com.hazelcast.internal.locksupport.operations.UnlockIfLeaseExpiredOperation" },
		{ -30064771072, "com.hazelcast.executor.impl.operations.CallableTaskOperation" },
		{ -30064771071, "com.hazelcast.executor.impl.operations.MemberCallableTaskOperation" },
		{ -30064771070, "com.hazelcast.executor.impl.RunnableAdapter" },
		{ -30064771069, "com.hazelcast.executor.impl.operations.CancellationOperation" },
		{ -30064771068, "com.hazelcast.executor.impl.operations.ShutdownOperation" },
		{ -25769803774, "com.hazelcast.multimap.impl.operations.ClearBackupOperation" },
		{ -25769803773, "com.hazelcast.multimap.impl.operations.ClearOperation" },
		{ -25769803769, "com.hazelcast.multimap.impl.operations.ContainsEntryOperation" },
		{ -25769803767, "com.hazelcast.multimap.impl.operations.CountOperation" },
		{ -25769803766, "com.hazelcast.multimap.impl.operations.EntrySetOperation" },
		{ -25769803765, "com.hazelcast.multimap.impl.operations.GetAllOperation" },
		{ -25769803762, "com.hazelcast.multimap.impl.operations.KeySetOperation" },
		{ -25769803761, "com.hazelcast.multimap.impl.operations.PutBackupOperation" },
		{ -25769803760, "com.hazelcast.multimap.impl.operations.PutOperation" },
		{ -25769803759, "com.hazelcast.multimap.impl.operations.RemoveAllBackupOperation" },
		{ -25769803758, "com.hazelcast.multimap.impl.operations.RemoveAllOperation" },
		{ -25769803757, "com.hazelcast.multimap.impl.operations.RemoveBackupOperation" },
		{ -25769803756, "com.hazelcast.multimap.impl.operations.RemoveOperation" },
		{ -25769803751, "com.hazelcast.multimap.impl.operations.SizeOperation" },
		{ -25769803750, "com.hazelcast.multimap.impl.operations.ValuesOperation" },
		{ -25769803749, "com.hazelcast.multimap.impl.txn.TxnCommitBackupOperation" },
		{ -25769803748, "com.hazelcast.multimap.impl.txn.TxnCommitOperation" },
		{ -25769803747, "com.hazelcast.multimap.impl.txn.TxnGenerateRecordIdOperation" },
		{ -25769803746, "com.hazelcast.multimap.impl.txn.TxnLockAndGetOperation" },
		{ -25769803745, "com.hazelcast.multimap.impl.txn.TxnPrepareBackupOperation" },
		{ -25769803744, "com.hazelcast.multimap.impl.txn.TxnPrepareOperation" },
		{ -25769803743, "com.hazelcast.multimap.impl.txn.TxnPutOperation" },
		{ -25769803742, "com.hazelcast.multimap.impl.txn.TxnPutBackupOperation" },
		{ -25769803741, "com.hazelcast.multimap.impl.txn.TxnRemoveOperation" },
		{ -25769803740, "com.hazelcast.multimap.impl.txn.TxnRemoveBackupOperation" },
		{ -25769803739, "com.hazelcast.multimap.impl.txn.TxnRemoveAllOperation" },
		{ -25769803738, "com.hazelcast.multimap.impl.txn.TxnRemoveAllBackupOperation" },
		{ -25769803737, "com.hazelcast.multimap.impl.txn.TxnRollbackOperation" },
		{ -25769803736, "com.hazelcast.multimap.impl.txn.TxnRollbackBackupOperation" },
		{ -25769803735, "com.hazelcast.multimap.impl.operations.MultiMapOperationFactory" },
		{ -25769803734, "com.hazelcast.multimap.impl.txn.MultiMapTransactionLogRecord" },
		{ -25769803733, "com.hazelcast.multimap.impl.MultiMapEventFilter" },
		{ -25769803732, "com.hazelcast.multimap.impl.MultiMapRecord" },
		{ -25769803731, "com.hazelcast.multimap.impl.operations.MultiMapReplicationOperation" },
		{ -25769803730, "com.hazelcast.multimap.impl.operations.MultiMapResponse" },
		{ -25769803729, "com.hazelcast.multimap.impl.operations.EntrySetResponse" },
		{ -25769803728, "com.hazelcast.multimap.impl.MultiMapMergeContainer" },
		{ -25769803727, "com.hazelcast.multimap.impl.operations.MergeOperation" },
		{ -25769803726, "com.hazelcast.multimap.impl.operations.MergeBackupOperation" },
		{ -25769803725, "com.hazelcast.multimap.impl.operations.DeleteOperation" },
		{ -25769803724, "com.hazelcast.multimap.impl.operations.DeleteBackupOperation" },
		{ -25769803723, "com.hazelcast.multimap.impl.operations.PutAllOperation" },
		{ -25769803722, "com.hazelcast.multimap.impl.operations.PutAllBackupOperation" },
		{ -25769803721, "com.hazelcast.multimap.impl.operations.MultiMapPutAllOperationFactory" },
		{ -21474836480, "com.hazelcast.collection.impl.queue.operations.OfferOperation" },
		{ -21474836479, "com.hazelcast.collection.impl.queue.operations.PollOperation" },
		{ -21474836478, "com.hazelcast.collection.impl.queue.operations.PeekOperation" },
		{ -21474836477, "com.hazelcast.collection.impl.queue.operations.OfferBackupOperation" },
		{ -21474836476, "com.hazelcast.collection.impl.queue.operations.PollBackupOperation" },
		{ -21474836475, "com.hazelcast.collection.impl.queue.operations.AddAllBackupOperation" },
		{ -21474836474, "com.hazelcast.collection.impl.queue.operations.AddAllOperation" },
		{ -21474836473, "com.hazelcast.collection.impl.queue.operations.ClearBackupOperation" },
		{ -21474836472, "com.hazelcast.collection.impl.queue.operations.ClearOperation" },
		{ -21474836471, "com.hazelcast.collection.impl.queue.operations.CompareAndRemoveBackupOperation" },
		{ -21474836470, "com.hazelcast.collection.impl.queue.operations.CompareAndRemoveOperation" },
		{ -21474836469, "com.hazelcast.collection.impl.queue.operations.ContainsOperation" },
		{ -21474836468, "com.hazelcast.collection.impl.queue.operations.DrainBackupOperation" },
		{ -21474836467, "com.hazelcast.collection.impl.queue.operations.DrainOperation" },
		{ -21474836466, "com.hazelcast.collection.impl.queue.operations.IteratorOperation" },
		{ -21474836465, "com.hazelcast.collection.impl.queue.QueueEvent" },
		{ -21474836464, "com.hazelcast.collection.impl.queue.QueueEventFilter" },
		{ -21474836463, "com.hazelcast.collection.impl.queue.QueueItem" },
		{ -21474836462, "com.hazelcast.collection.impl.queue.operations.QueueReplicationOperation" },
		{ -21474836461, "com.hazelcast.collection.impl.queue.operations.RemoveBackupOperation" },
		{ -21474836460, "com.hazelcast.collection.impl.queue.operations.RemoveOperation" },
		{ -21474836458, "com.hazelcast.collection.impl.queue.operations.SizeOperation" },
		{ -21474836457, "com.hazelcast.collection.impl.txnqueue.operations.TxnOfferBackupOperation" },
		{ -21474836456, "com.hazelcast.collection.impl.txnqueue.operations.TxnOfferOperation" },
		{ -21474836455, "com.hazelcast.collection.impl.txnqueue.operations.TxnPollBackupOperation" },
		{ -21474836454, "com.hazelcast.collection.impl.txnqueue.operations.TxnPollOperation" },
		{ -21474836453, "com.hazelcast.collection.impl.txnqueue.operations.TxnPrepareBackupOperation" },
		{ -21474836452, "com.hazelcast.collection.impl.txnqueue.operations.TxnPrepareOperation" },
		{ -21474836451, "com.hazelcast.collection.impl.txnqueue.operations.TxnReserveOfferOperation" },
		{ -21474836450, "com.hazelcast.collection.impl.txnqueue.operations.TxnReserveOfferBackupOperation" },
		{ -21474836449, "com.hazelcast.collection.impl.txnqueue.operations.TxnReservePollOperation" },
		{ -21474836448, "com.hazelcast.collection.impl.txnqueue.operations.TxnReservePollBackupOperation" },
		{ -21474836447, "com.hazelcast.collection.impl.txnqueue.operations.TxnRollbackBackupOperation" },
		{ -21474836446, "com.hazelcast.collection.impl.txnqueue.operations.TxnRollbackOperation" },
		{ -21474836445, "com.hazelcast.collection.impl.queue.operations.CheckAndEvictOperation" },
		{ -21474836444, "com.hazelcast.collection.impl.txnqueue.operations.QueueTransactionRollbackOperation" },
		{ -21474836443, "com.hazelcast.collection.impl.txnqueue.TxQueueItem" },
		{ -21474836442, "com.hazelcast.collection.impl.queue.QueueContainer" },
		{ -21474836441, "com.hazelcast.collection.impl.txnqueue.operations.TxnPeekOperation" },
		{ -21474836440, "com.hazelcast.collection.impl.queue.operations.IsEmptyOperation" },
		{ -21474836439, "com.hazelcast.collection.impl.queue.operations.RemainingCapacityOperation" },
		{ -21474836438, "com.hazelcast.collection.impl.txnqueue.operations.TxnCommitOperation" },
		{ -21474836437, "com.hazelcast.collection.impl.txnqueue.operations.TxnCommitBackupOperation" },
		{ -21474836436, "com.hazelcast.collection.impl.queue.operations.QueueMergeOperation" },
		{ -21474836435, "com.hazelcast.collection.impl.queue.operations.QueueMergeBackupOperation" },
		{ -17179869184, "com.hazelcast.map.impl.operation.PutOperation" },
		{ -17179869183, "com.hazelcast.map.impl.operation.GetOperation" },
		{ -17179869182, "com.hazelcast.map.impl.operation.RemoveOperation" },
		{ -17179869181, "com.hazelcast.map.impl.operation.PutBackupOperation" },
		{ -17179869180, "com.hazelcast.map.impl.operation.RemoveBackupOperation" },
		{ -17179869179, "com.hazelcast.map.impl.querycache.accumulator.AccumulatorInfo" },
		{ -17179869178, "com.hazelcast.map.impl.DataCollection" },
		{ -17179869177, "com.hazelcast.map.impl.MapEntries" },
		{ -17179869176, "com.hazelcast.map.impl.SimpleEntryView" },
		{ -17179869175, "com.hazelcast.map.impl.query.QueryResultRow" },
		{ -17179869174, "com.hazelcast.map.impl.query.QueryResult" },
		{ -17179869173, "com.hazelcast.map.impl.operation.EvictBackupOperation" },
		{ -17179869172, "com.hazelcast.map.impl.operation.ContainsKeyOperation" },
		{ -17179869171, "com.hazelcast.map.impl.iterator.MapKeysWithCursor" },
		{ -17179869170, "com.hazelcast.map.impl.iterator.MapEntriesWithCursor" },
		{ -17179869169, "com.hazelcast.map.impl.operation.SetOperation" },
		{ -17179869168, "com.hazelcast.map.impl.operation.LoadMapOperation" },
		{ -17179869167, "com.hazelcast.map.impl.operation.KeyLoadStatusOperation" },
		{ -17179869166, "com.hazelcast.map.impl.operation.LoadAllOperation" },
		{ -17179869165, "com.hazelcast.map.impl.operation.EntryBackupOperation" },
		{ -17179869164, "com.hazelcast.map.impl.operation.EntryOperation" },
		{ -17179869163, "com.hazelcast.map.impl.operation.PutAllOperation" },
		{ -17179869162, "com.hazelcast.map.impl.operation.PutAllBackupOperation" },
		{ -17179869161, "com.hazelcast.map.impl.operation.RemoveIfSameOperation" },
		{ -17179869160, "com.hazelcast.map.impl.operation.ReplaceOperation" },
		{ -17179869159, "com.hazelcast.map.impl.operation.MapSizeOperation" },
		{ -17179869158, "com.hazelcast.map.impl.operation.ClearBackupOperation" },
		{ -17179869157, "com.hazelcast.map.impl.operation.ClearOperation" },
		{ -17179869156, "com.hazelcast.map.impl.operation.DeleteOperation" },
		{ -17179869155, "com.hazelcast.map.impl.operation.EvictOperation" },
		{ -17179869154, "com.hazelcast.map.impl.operation.EvictAllOperation" },
		{ -17179869153, "com.hazelcast.map.impl.operation.EvictAllBackupOperation" },
		{ -17179869152, "com.hazelcast.map.impl.operation.GetAllOperation" },
		{ -17179869151, "com.hazelcast.map.impl.operation.MapIsEmptyOperation" },
		{ -17179869150, "com.hazelcast.internal.nearcache.impl.invalidation.SingleNearCacheInvalidation" },
		{ -17179869149, "com.hazelcast.internal.nearcache.impl.invalidation.BatchNearCacheInvalidation" },
		{ -17179869148, "com.hazelcast.map.impl.operation.IsPartitionLoadedOperation" },
		{ -17179869147, "com.hazelcast.map.impl.operation.PartitionWideEntryOperation" },
		{ -17179869146, "com.hazelcast.map.impl.operation.PartitionWideEntryBackupOperation" },
		{ -17179869145, "com.hazelcast.map.impl.operation.PartitionWideEntryWithPredicateOperation" },
		{ -17179869144, "com.hazelcast.map.impl.operation.PartitionWideEntryWithPredicateBackupOperation" },
		{ -17179869143, "com.hazelcast.map.impl.operation.AddIndexOperation" },
		{ -17179869142, "com.hazelcast.map.impl.operation.AwaitMapFlushOperation" },
		{ -17179869141, "com.hazelcast.map.impl.operation.ContainsValueOperation" },
		{ -17179869140, "com.hazelcast.map.impl.operation.GetEntryViewOperation" },
		{ -17179869139, "com.hazelcast.map.impl.operation.MapFetchEntriesOperation" },
		{ -17179869138, "com.hazelcast.map.impl.operation.MapFetchKeysOperation" },
		{ -17179869137, "com.hazelcast.map.impl.operation.MapFlushBackupOperation" },
		{ -17179869136, "com.hazelcast.map.impl.operation.MapFlushOperation" },
		{ -17179869135, "com.hazelcast.map.impl.operation.MultipleEntryBackupOperation" },
		{ -17179869134, "com.hazelcast.map.impl.operation.MultipleEntryOperation" },
		{ -17179869133, "com.hazelcast.map.impl.operation.MultipleEntryWithPredicateBackupOperation" },
		{ -17179869132, "com.hazelcast.map.impl.operation.MultipleEntryWithPredicateOperation" },
		{ -17179869131, "com.hazelcast.map.impl.operation.NotifyMapFlushOperation" },
		{ -17179869130, "com.hazelcast.map.impl.operation.PutIfAbsentOperation" },
		{ -17179869129, "com.hazelcast.map.impl.operation.PutFromLoadAllOperation" },
		{ -17179869128, "com.hazelcast.map.impl.operation.PutFromLoadAllBackupOperation" },
		{ -17179869127, "com.hazelcast.map.impl.query.QueryPartitionOperation" },
		{ -17179869126, "com.hazelcast.map.impl.query.QueryOperation" },
		{ -17179869125, "com.hazelcast.map.impl.operation.PutTransientOperation" },
		{ -17179869124, "com.hazelcast.map.impl.operation.ReplaceIfSameOperation" },
		{ -17179869123, "com.hazelcast.map.impl.operation.TryPutOperation" },
		{ -17179869122, "com.hazelcast.map.impl.operation.TryRemoveOperation" },
		{ -17179869121, "com.hazelcast.map.impl.tx.TxnLockAndGetOperation" },
		{ -17179869120, "com.hazelcast.map.impl.tx.TxnDeleteOperation" },
		{ -17179869119, "com.hazelcast.map.impl.tx.TxnPrepareOperation" },
		{ -17179869118, "com.hazelcast.map.impl.tx.TxnPrepareBackupOperation" },
		{ -17179869117, "com.hazelcast.map.impl.tx.TxnRollbackOperation" },
		{ -17179869116, "com.hazelcast.map.impl.tx.TxnRollbackBackupOperation" },
		{ -17179869115, "com.hazelcast.map.impl.tx.TxnSetOperation" },
		{ -17179869114, "com.hazelcast.map.impl.tx.TxnUnlockOperation" },
		{ -17179869113, "com.hazelcast.map.impl.tx.TxnUnlockBackupOperation" },
		{ -17179869112, "com.hazelcast.map.impl.operation.IsPartitionLoadedOperationFactory" },
		{ -17179869111, "com.hazelcast.map.impl.operation.AddIndexOperationFactory" },
		{ -17179869110, "com.hazelcast.map.impl.operation.ClearOperationFactory" },
		{ -17179869109, "com.hazelcast.map.impl.operation.ContainsValueOperationFactory" },
		{ -17179869108, "com.hazelcast.map.impl.operation.EvictAllOperationFactory" },
		{ -17179869107, "com.hazelcast.map.impl.operation.IsEmptyOperationFactory" },
		{ -17179869106, "com.hazelcast.map.impl.operation.KeyLoadStatusOperationFactory" },
		{ -17179869105, "com.hazelcast.map.impl.operation.MapFlushOperationFactory" },
		{ -17179869104, "com.hazelcast.map.impl.operation.MapGetAllOperationFactory" },
		{ -17179869103, "com.hazelcast.map.impl.operation.MapLoadAllOperationFactory" },
		{ -17179869102, "com.hazelcast.map.impl.operation.PartitionWideEntryOperationFactory" },
		{ -17179869101, "com.hazelcast.map.impl.operation.PartitionWideEntryWithPredicateOperationFactory" },
		{ -17179869100, "com.hazelcast.map.impl.operation.PutAllPartitionAwareOperationFactory" },
		{ -17179869099, "com.hazelcast.map.impl.operation.SizeOperationFactory" },
		{ -17179869098, "com.hazelcast.map.impl.operation.MultipleEntryOperationFactory" },
		{ -17179869097, "com.hazelcast.map.impl.EntryEventFilter" },
		{ -17179869096, "com.hazelcast.map.impl.EventListenerFilter" },
		{ -17179869095, "com.hazelcast.map.impl.MapPartitionLostEventFilter" },
		{ -17179869094, "com.hazelcast.map.impl.operation.AddInterceptorOperation" },
		{ -17179869093, "com.hazelcast.map.impl.operation.MapReplicationOperation" },
		{ -17179869092, "com.hazelcast.map.impl.operation.PostJoinMapOperation" },
		{ -17179869090, "com.hazelcast.query.impl.MapIndexInfo" },
		{ -17179869089, "com.hazelcast.map.impl.operation.PostJoinMapOperation$InterceptorInfo" },
		{ -17179869088, "com.hazelcast.map.impl.operation.RemoveInterceptorOperation" },
		{ -17179869087, "com.hazelcast.map.impl.query.QueryEventFilter" },
		{ -17179869084, "com.hazelcast.map.impl.nearcache.invalidation.UuidFilter" },
		{ -17179869083, "com.hazelcast.map.impl.tx.MapTransactionLogRecord" },
		{ -17179869082, "com.hazelcast.map.impl.tx.VersionedValue" },
		{ -17179869081, "com.hazelcast.map.impl.operation.MapReplicationStateHolder" },
		{ -17179869080, "com.hazelcast.map.impl.operation.WriteBehindStateHolder" },
		{ -17179869079, "com.hazelcast.map.impl.query.AggregationResult" },
		{ -17179869078, "com.hazelcast.map.impl.query.Query" },
		{ -17179869076, "com.hazelcast.map.impl.operation.MapGetInvalidationMetaDataOperation" },
		{ -17179869075, "com.hazelcast.map.impl.operation.MapGetInvalidationMetaDataOperation$MetaDataResponse" },
		{ -17179869074, "com.hazelcast.map.impl.operation.MapNearCacheStateHolder" },
		{ -17179869073, "com.hazelcast.client.impl.protocol.task.map.MapAssignAndGetUuidsOperation" },
		{ -17179869072, "com.hazelcast.client.impl.protocol.task.map.MapAssignAndGetUuidsOperationFactory" },
		{ -17179869071, "com.hazelcast.map.impl.querycache.subscriber.operation.DestroyQueryCacheOperation" },
		{ -17179869070, "com.hazelcast.map.impl.querycache.subscriber.operation.MadePublishableOperation" },
		{ -17179869069, "com.hazelcast.map.impl.querycache.subscriber.operation.MadePublishableOperationFactory" },
		{ -17179869068, "com.hazelcast.map.impl.querycache.subscriber.operation.PublisherCreateOperation" },
		{ -17179869067, "com.hazelcast.map.impl.querycache.subscriber.operation.ReadAndResetAccumulatorOperation" },
		{ -17179869066, "com.hazelcast.map.impl.querycache.subscriber.operation.SetReadCursorOperation" },
		{ -17179869065, "com.hazelcast.map.impl.querycache.accumulator.ConsumeAccumulatorOperation" },
		{ -17179869064, "com.hazelcast.map.impl.LazyMapEntry" },
		{ -17179869063, "com.hazelcast.map.impl.operation.TriggerLoadIfNeededOperation" },
		{ -17179869062, "com.hazelcast.map.impl.operation.IsKeyLoadFinishedOperation" },
		{ -17179869061, "com.hazelcast.map.impl.operation.RemoveFromLoadAllOperation" },
		{ -17179869060, "com.hazelcast.map.impl.EntryRemovingProcessor" },
		{ -17179869059, "com.hazelcast.map.impl.operation.EntryOffloadableSetUnlockOperation" },
		{ -17179869058, "com.hazelcast.map.impl.LockAwareLazyMapEntry" },
		{ -17179869057, "com.hazelcast.map.impl.operation.MapFetchWithQueryOperation" },
		{ -17179869056, "com.hazelcast.map.impl.query.ResultSegment" },
		{ -17179869055, "com.hazelcast.map.impl.operation.EvictBatchBackupOperation" },
		{ -17179869054, "com.hazelcast.map.impl.journal.MapEventJournalSubscribeOperation" },
		{ -17179869053, "com.hazelcast.map.impl.journal.MapEventJournalReadOperation" },
		{ -17179869052, "com.hazelcast.map.impl.journal.DeserializingEventJournalMapEvent" },
		{ -17179869051, "com.hazelcast.map.impl.journal.InternalEventJournalMapEvent" },
		{ -17179869050, "com.hazelcast.map.impl.journal.MapEventJournalReadResultSetImpl" },
		{ -17179869049, "com.hazelcast.map.impl.operation.MergeOperationFactory" },
		{ -17179869048, "com.hazelcast.map.impl.operation.MergeOperation" },
		{ -17179869047, "com.hazelcast.map.impl.operation.SetTtlOperation" },
		{ -17179869046, "com.hazelcast.map.impl.operation.SetTtlBackupOperation" },
		{ -17179869045, "com.hazelcast.map.impl.MerkleTreeNodeEntries" },
		{ -17179869044, "com.hazelcast.map.impl.operation.AddIndexBackupOperation" },
		{ -17179869043, "com.hazelcast.map.impl.tx.TxnSetBackupOperation" },
		{ -17179869042, "com.hazelcast.map.impl.tx.TxnDeleteBackupOperation" },
		{ -17179869041, "com.hazelcast.map.impl.operation.SetWithExpiryOperation" },
		{ -17179869040, "com.hazelcast.map.impl.operation.PutWithExpiryOperation" },
		{ -17179869039, "com.hazelcast.map.impl.operation.PutTransientWithExpiryOperation" },
		{ -17179869038, "com.hazelcast.map.impl.operation.PutIfAbsentWithExpiryOperation" },
		{ -17179869037, "com.hazelcast.map.impl.operation.PutTransientBackupOperation" },
		{ -17179869036, "com.hazelcast.map.impl.ComputeIfPresentEntryProcessor" },
		{ -17179869035, "com.hazelcast.map.impl.ComputeIfAbsentEntryProcessor" },
		{ -17179869034, "com.hazelcast.map.impl.KeyValueConsumingEntryProcessor" },
		{ -17179869033, "com.hazelcast.map.impl.ComputeEntryProcessor" },
		{ -17179869032, "com.hazelcast.map.impl.MergeEntryProcessor" },
		{ -17179869031, "com.hazelcast.map.impl.MapEntryReplacingEntryProcessor" },
		{ -17179869030, "com.hazelcast.internal.monitor.impl.LocalRecordStoreStatsImpl" },
		{ -17179869029, "com.hazelcast.map.impl.operation.MapFetchIndexOperation" },
		{ -17179869028, "com.hazelcast.internal.iteration.IndexIterationPointer" },
		{ -17179869027, "com.hazelcast.map.impl.operation.MapFetchIndexOperation$MapFetchIndexOperationResult" },
		{ -12884901886, "com.hazelcast.client.impl.operations.GetConnectedClientsOperation" },
		{ -12884901884, "com.hazelcast.client.impl.operations.OperationFactoryWrapper" },
		{ -8589934591, "com.hazelcast.internal.partition.PartitionRuntimeState" },
		{ -8589934590, "com.hazelcast.internal.partition.operation.AssignPartitions" },
		{ -8589934589, "com.hazelcast.internal.partition.operation.PartitionBackupReplicaAntiEntropyOperation" },
		{ -8589934588, "com.hazelcast.internal.partition.operation.FetchPartitionStateOperation" },
		{ -8589934587, "com.hazelcast.internal.partition.operation.HasOngoingMigration" },
		{ -8589934586, "com.hazelcast.internal.partition.operation.MigrationCommitOperation" },
		{ -8589934585, "com.hazelcast.internal.partition.operation.PartitionStateOperation" },
		{ -8589934584, "com.hazelcast.internal.partition.operation.PromotionCommitOperation" },
		{ -8589934583, "com.hazelcast.internal.partition.operation.PartitionReplicaSyncRequest" },
		{ -8589934582, "com.hazelcast.internal.partition.operation.PartitionReplicaSyncResponse" },
		{ -8589934581, "com.hazelcast.internal.partition.operation.PartitionReplicaSyncRetryResponse" },
		{ -8589934580, "com.hazelcast.internal.partition.operation.SafeStateCheckOperation" },
		{ -8589934579, "com.hazelcast.internal.partition.operation.ShutdownRequestOperation" },
		{ -8589934578, "com.hazelcast.internal.partition.operation.ShutdownResponseOperation" },
		{ -8589934577, "com.hazelcast.internal.partition.ReplicaFragmentMigrationState" },
		{ -8589934576, "com.hazelcast.internal.partition.operation.MigrationOperation" },
		{ -8589934575, "com.hazelcast.internal.partition.operation.MigrationRequestOperation" },
		{ -8589934574, "com.hazelcast.internal.partition.NonFragmentedServiceNamespace" },
		{ -8589934573, "com.hazelcast.internal.partition.PartitionReplica" },
		{ -8589934572, "com.hazelcast.internal.partition.operation.PublishCompletedMigrationsOperation" },
		{ -8589934571, "com.hazelcast.internal.partition.operation.PartitionStateCheckOperation" },
		{ -8589934570, "com.hazelcast.internal.partition.ReplicaMigrationEventImpl" },
		{ -8589934569, "com.hazelcast.internal.partition.MigrationStateImpl" },
		{ -8589934568, "com.hazelcast.internal.partition.PartitionLostEventImpl" },
		{ -8589934567, "com.hazelcast.internal.partition.operation.PartitionReplicaSyncRequestOffloadable" },
		{ -4294967296, "com.hazelcast.spi.impl.operationservice.impl.responses.NormalResponse" },
		{ -4294967295, "com.hazelcast.spi.impl.operationservice.impl.operations.Backup" },
		{ -4294967294, "com.hazelcast.spi.impl.operationservice.impl.responses.BackupAckResponse" },
		{ -4294967293, "com.hazelcast.spi.impl.operationservice.impl.operations.PartitionIteratingOperation" },
		{ -4294967292, "com.hazelcast.spi.impl.operationservice.impl.operations.PartitionIteratingOperation$PartitionResponse" },
		{ -4294967291, "com.hazelcast.spi.impl.operationservice.BinaryOperationFactory" },
		{ -4294967290, "com.hazelcast.spi.impl.eventservice.impl.EventEnvelope" },
		{ -4294967289, "com.hazelcast.spi.impl.SerializableList" },
		{ -4294967288, "com.hazelcast.spi.impl.operationservice.impl.responses.CallTimeoutResponse" },
		{ -4294967287, "com.hazelcast.spi.impl.operationservice.impl.responses.ErrorResponse" },
		{ -4294967286, "com.hazelcast.spi.impl.eventservice.impl.operations.DeregistrationOperation" },
		{ -4294967285, "com.hazelcast.spi.impl.eventservice.impl.operations.OnJoinRegistrationOperation" },
		{ -4294967284, "com.hazelcast.spi.impl.eventservice.impl.operations.RegistrationOperation" },
		{ -4294967283, "com.hazelcast.spi.impl.eventservice.impl.operations.SendEventOperation" },
		{ -4294967282, "com.hazelcast.spi.impl.proxyservice.impl.operations.InitializeDistributedObjectOperation" },
		{ -4294967281, "com.hazelcast.spi.impl.proxyservice.impl.operations.DistributedObjectDestroyOperation" },
		{ -4294967280, "com.hazelcast.spi.impl.proxyservice.impl.operations.PostJoinProxyOperation" },
		{ -4294967279, "com.hazelcast.spi.impl.eventservice.impl.TrueEventFilter" },
		{ -4294967278, "com.hazelcast.spi.impl.UnmodifiableLazyList" },
		{ -4294967277, "com.hazelcast.spi.impl.operationservice.OperationControl" },
		{ -4294967276, "com.hazelcast.internal.services.DistributedObjectNamespace" },
		{ -4294967275, "com.hazelcast.spi.impl.eventservice.impl.Registration" },
		{ -4294967274, "com.hazelcast.spi.impl.tenantcontrol.NoopTenantControl" },
		{ -4294967273, "com.hazelcast.security.UsernamePasswordCredentials" },
		{ -4294967272, "com.hazelcast.security.SimpleTokenCredentials" },
		{ -4294967271, "com.hazelcast.spi.impl.proxyservice.impl.DistributedObjectEventPacket" },
		{ -4294967270, "com.hazelcast.spi.impl.tenantcontrol.impl.TenantControlReplicationOperation" },
		{ 0, "com.hazelcast.internal.cluster.impl.operations.AuthenticationFailureOp" },
		{ 1, "com.hazelcast.cluster.Address" },
		{ 2, "com.hazelcast.cluster.impl.MemberImpl" },
		{ 3, "com.hazelcast.internal.cluster.impl.operations.HeartbeatOp" },
		{ 4, "com.hazelcast.internal.cluster.impl.ConfigCheck" },
		{ 5, "com.hazelcast.internal.cluster.impl.MemberHandshake" },
		{ 6, "com.hazelcast.internal.cluster.impl.operations.MembersUpdateOp" },
		{ 7, "com.hazelcast.internal.cluster.impl.operations.FinalizeJoinOp" },
		{ 8, "com.hazelcast.internal.cluster.impl.operations.BeforeJoinCheckFailureOp" },
		{ 9, "com.hazelcast.internal.cluster.impl.operations.CommitClusterStateOp" },
		{ 10, "com.hazelcast.internal.cluster.impl.operations.ConfigMismatchOp" },
		{ 11, "com.hazelcast.internal.cluster.impl.operations.ClusterMismatchOp" },
		{ 12, "com.hazelcast.internal.cluster.impl.operations.SplitBrainMergeValidationOp" },
		{ 13, "com.hazelcast.internal.cluster.impl.operations.JoinRequestOp" },
		{ 14, "com.hazelcast.internal.cluster.impl.operations.LockClusterStateOp" },
		{ 15, "com.hazelcast.internal.cluster.impl.operations.JoinMastershipClaimOp" },
		{ 16, "com.hazelcast.internal.cluster.impl.operations.WhoisMasterOp" },
		{ 17, "com.hazelcast.instance.EndpointQualifier" },
		{ 18, "com.hazelcast.internal.cluster.impl.operations.MergeClustersOp" },
		{ 19, "com.hazelcast.internal.cluster.impl.operations.OnJoinOp" },
		{ 20, "com.hazelcast.internal.cluster.impl.operations.RollbackClusterStateOp" },
		{ 21, "com.hazelcast.internal.cluster.impl.operations.MasterResponseOp" },
		{ 22, "com.hazelcast.internal.cluster.impl.operations.ShutdownNodeOp" },
		{ 23, "com.hazelcast.internal.cluster.impl.operations.TriggerMemberListPublishOp" },
		{ 24, "com.hazelcast.internal.cluster.impl.ClusterStateTransactionLogRecord" },
		{ 25, "com.hazelcast.internal.cluster.MemberInfo" },
		{ 26, "com.hazelcast.internal.cluster.impl.JoinMessage" },
		{ 27, "com.hazelcast.internal.cluster.impl.JoinRequest" },
		{ 28, "com.hazelcast.internal.partition.MigrationInfo" },
		{ 29, "com.hazelcast.version.MemberVersion" },
		{ 30, "com.hazelcast.internal.cluster.impl.ClusterStateChange" },
		{ 31, "com.hazelcast.internal.cluster.impl.SplitBrainJoinMessage" },
		{ 32, "com.hazelcast.version.Version" },
		{ 33, "com.hazelcast.internal.cluster.impl.operations.FetchMembersViewOp" },
		{ 34, "com.hazelcast.internal.cluster.impl.operations.ExplicitSuspicionOp" },
		{ 35, "com.hazelcast.internal.cluster.impl.MembersView" },
		{ 36, "com.hazelcast.internal.cluster.impl.operations.TriggerExplicitSuspicionOp" },
		{ 37, "com.hazelcast.internal.cluster.impl.MembersViewMetadata" },
		{ 38, "com.hazelcast.internal.cluster.impl.operations.HeartbeatComplaintOp" },
		{ 39, "com.hazelcast.internal.cluster.impl.operations.PromoteLiteMemberOp" },
		{ 40, "com.hazelcast.cluster.impl.VectorClock" },
	    { 0, NULL }
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

static int hf_hazelcast_ds_version_major = -1;
static int hf_hazelcast_ds_version_minor = -1;

// DataSerializable
static int hf_hazelcast_ds_class_name = -1;

// IdentifiedDataSerializable
static int hf_hazelcast_ids_factory_id = -1;
static int hf_hazelcast_ids_class_id = -1;
static int hf_hazelcast_ids_mapped_class_name = -1;

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

    col_clear(pinfo->cinfo, COL_INFO);

    if (flag_ids) {
    	proto_tree_add_item(tree, hf_hazelcast_ids_factory_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    	proto_tree_add_item(tree, hf_hazelcast_ids_class_id, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
    	proto_tree_add_item(tree, hf_hazelcast_ids_mapped_class_name, tvb, offset, 8, ENC_BIG_ENDIAN);
    	gint64 class_id = tvb_get_ntohi64(tvb, offset);
    	// printf("IDS %ld\n", class_id);

    	offset += 8;
    	col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
    			val64_to_str(class_id, ids_classes, "Unknown (%ld)"));
    } else {
    	guint16 name_len = tvb_get_ntohs(tvb, offset);
		offset += 2;
		gchar* ds_classname = (gchar *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, name_len, ENC_ASCII|ENC_NA);
    	proto_tree_add_item(tree, hf_hazelcast_ds_class_name, tvb, offset, name_len, ENC_BIG_ENDIAN);
    	offset += name_len;
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s", ds_classname);
    }


    if (flag_versioned) {
		proto_tree_add_item(tree, hf_hazelcast_ds_version_major, tvb, offset++, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_hazelcast_ds_version_minor, tvb, offset++, 1, ENC_BIG_ENDIAN);
    }
    return offset;
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
	    { &hf_hazelcast_ids_factory_id,
	        { "IDS Factory ID", "hazelcast.identifieddataserializable.factoryId",
	        FT_INT32, BASE_DEC,
	        NULL, 0x0,
	        NULL, HFILL }
	    },
	    { &hf_hazelcast_ids_class_id,
	        { "IDS Class ID", "hazelcast.identifieddataserializable.classId",
			FT_INT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
	    },
	    { &hf_hazelcast_ds_version_major,
	        { "Version major", "hazelcast.dataserializable.version.major",
			FT_UINT8, BASE_DEC,
	        NULL, 0x0,
	        NULL, HFILL }
	    },
	    { &hf_hazelcast_ds_version_minor,
	        { "Version minor", "hazelcast.dataserializable.version.minor",
			FT_UINT8, BASE_DEC,
	        NULL, 0x0,
	        NULL, HFILL }
	    },
	    { &hf_hazelcast_ds_class_name,
	        { "DataSerializable class", "hazelcast.dataserializable.class",
			FT_STRING, BASE_NONE,
	        NULL, 0x0,
	        NULL, HFILL }
	    },
	    { &hf_hazelcast_ids_mapped_class_name,
	        { "IdentifiedDataSerializable class", "hazelcast.identifieddataserializable.class",
			FT_INT64, BASE_DEC|BASE_VAL64_STRING,
			VALS64(ids_classes), 0x0,
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
    static dissector_handle_t hazelcast_handle;

    hazelcast_handle = create_dissector_handle(dissect_hazelcast, proto_hazelcast);
    dissector_add_uint("tcp.port", HAZELCAST_TCP_PORT1, hazelcast_handle);
    dissector_add_uint("tcp.port", HAZELCAST_TCP_PORT2, hazelcast_handle);
    dissector_add_uint("tcp.port", HAZELCAST_TCP_PORT3, hazelcast_handle);
}
