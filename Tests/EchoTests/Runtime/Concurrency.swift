import Testing
@testable import Echo

extension EchoTests {
  @Test
  func concurrencyRuntimeFlagsDecodeModernTaskFeatures() {
    let create = TaskCreateFlags(
      bits: (1 << 8) | (1 << 10) | (1 << 14) | (1 << 15) | (1 << 16) | 0x19
    )
    #expect(create.requestedPriority == .userInitiated)
    #expect(create.isChildTask)
    #expect(create.copiesTaskLocals)
    #expect(create.isDiscardingTask)
    #expect(create.isTaskFunctionConsumed)
    #expect(create.isImmediateTask)
    #expect(create.enqueuesJob == false)

    let job = JobFlags(
      bits: (1 << 24) | (1 << 25) | (1 << 26) | (1 << 28) | (1 << 29) | (1 << 30)
        | (UInt32(JobPriority.utility.rawValue) << 8) | UInt32(JobKind.task.rawValue)
    )
    #expect(job.kind == .task)
    #expect(job.priority == .utility)
    #expect(job.isAsyncTask)
    #expect(job.isChildTask)
    #expect(job.isFutureTask)
    #expect(job.isGroupChildTask)
    #expect(job.isAsyncLetTask)
    #expect(job.hasInitialTaskExecutorPreference)
    #expect(job.hasInitialTaskName)
  }

  @Test
  func concurrencyRuntimeRecordFlagsDecodeKnownAndUnknownValues() {
    #expect(TaskGroupFlags(bits: 1 << 8).discardsResults)

    #expect(TaskStatusRecordFlags(bits: 5).kind == .taskExecutorPreference)
    #expect(TaskStatusRecordFlags(bits: 127).kind == nil)

    #expect(TaskOptionRecordFlags(bits: 3).kind == .asyncLetWithBuffer)
    #expect(TaskOptionRecordFlags(bits: UInt(UInt8.max)).kind == .runInline)

    let continuation = AsyncContinuationFlags(bits: 0xF)
    #expect(continuation.canThrow)
    #expect(continuation.hasExecutorOverride)
    #expect(continuation.isPreawaited)
    #expect(continuation.isExecutorSwitchForced)
  }

  @Test
  func executorReferencesDecodeImmediateDefaultAndCustomExecutors() {
    let immediate = SerialExecutorReference(identity: nil, implementation: 2)
    #expect(immediate.isGeneric)
    #expect(immediate.isSynchronousStart)
    #expect(immediate.kind == .immediate)
    #expect(immediate.witnessTable == nil)

    let storage = UnsafeMutableRawPointer.allocate(byteCount: 16, alignment: 8)
    defer { storage.deallocate() }

    let defaultActor = SerialExecutorReference(
      identity: UnsafeRawPointer(storage), implementation: 0
    )
    #expect(defaultActor.isDefaultActor)
    #expect(defaultActor.witnessTable == nil)

    let complex = SerialExecutorReference(
      identity: UnsafeRawPointer(storage),
      implementation: UInt(bitPattern: UnsafeRawPointer(storage)) | 1
    )
    #expect(complex.kind == .complexEquality)
    #expect(complex.witnessTable == UnsafeRawPointer(storage))

    let undefined = TaskExecutorReference(identity: nil, implementation: 0)
    #expect(undefined.isUndefined)
    #expect(undefined.witnessTable == nil)

    let taskExecutor = TaskExecutorReference(
      identity: UnsafeRawPointer(storage),
      implementation: UInt(bitPattern: UnsafeRawPointer(storage))
    )
    #expect(taskExecutor.isDefined)
    #expect(taskExecutor.kind == .ordinary)
    #expect(taskExecutor.witnessTable == UnsafeRawPointer(storage))
  }
}
