//
//  Concurrency.swift
//  Echo
//
//  Copyright © 2026 Echo contributors.
//

/// A schedulable Swift-concurrency job kind.
///
/// Kinds from `firstReserved` onwards are runtime implementation details and
/// may change in a future Swift runtime.
public enum JobKind: UInt, Sendable {
  /// An `AsyncTask` job.
  case task = 0

  /// A job used to run work inline on a default actor.
  case defaultActorInline = 192

  /// A job used to run separately scheduled default-actor work.
  case defaultActorSeparate = 193

  /// A job used by a default-actor executor override.
  case defaultActorOverride = 194

  /// A private nullary continuation job.
  case nullaryContinuation = 195

  /// A private isolated-deinitialization job.
  case isolatedDeinit = 196

  /// The first kind reserved for Swift runtime implementation jobs.
  public static let firstReserved = JobKind.defaultActorInline
}

/// A Swift-concurrency job priority.
public enum JobPriority: UInt, Sendable {
  case userInteractive = 0x21
  case userInitiated = 0x19
  case `default` = 0x15
  case utility = 0x11
  case background = 0x09
  case unspecified = 0
}

/// Flags supplied when the runtime creates an asynchronous task.
///
/// These flags describe task creation, not an already-running task. Decode
/// them only from storage whose lifetime and synchronization you control.
public struct TaskCreateFlags: Equatable, Sendable {
  /// Raw runtime flag bits.
  public let bits: UInt

  /// Creates flags from their Swift runtime representation.
  public init(bits: UInt) {
    self.bits = bits
  }

  /// The requested priority, or `nil` for a runtime value Echo does not know.
  public var requestedPriority: JobPriority? {
    JobPriority(rawValue: bits & 0xFF)
  }

  /// Whether the created task is a child of the current task.
  public var isChildTask: Bool { bits & (1 << 8) != 0 }

  /// Whether this task is intended to run inline.
  public var isInlineTask: Bool { bits & (1 << 9) != 0 }

  /// Whether task-local values are copied into the new task.
  public var copiesTaskLocals: Bool { bits & (1 << 10) != 0 }

  /// Whether the task inherits its execution context.
  public var inheritsContext: Bool { bits & (1 << 11) != 0 }

  /// Whether the new task should be enqueued immediately.
  public var enqueuesJob: Bool { bits & (1 << 12) != 0 }

  /// Whether a group task is added even if it has already become cancelled.
  public var addsPendingGroupTaskUnconditionally: Bool { bits & (1 << 13) != 0 }

  /// Whether the task discards its result.
  public var isDiscardingTask: Bool { bits & (1 << 14) != 0 }

  /// Whether the task function uses consuming (`@callee_owned`) ownership.
  ///
  /// This flag was introduced in Swift 6.1.
  public var isTaskFunctionConsumed: Bool { bits & (1 << 15) != 0 }

  /// Whether the task is an immediate task.
  public var isImmediateTask: Bool { bits & (1 << 16) != 0 }
}

/// Flags stored on a schedulable job.
public struct JobFlags: Equatable, Sendable {
  /// Raw runtime flag bits.
  public let bits: UInt32

  /// Creates flags from their Swift runtime representation.
  public init(bits: UInt32) {
    self.bits = bits
  }

  /// The job kind, or `nil` for a future runtime-defined kind.
  public var kind: JobKind? {
    JobKind(rawValue: UInt(bits & 0xFF))
  }

  /// The job priority, or `nil` for a future runtime-defined priority.
  public var priority: JobPriority? {
    JobPriority(rawValue: UInt((bits >> 8) & 0xFF))
  }

  /// Whether this job is an asynchronous task.
  public var isAsyncTask: Bool { kind == .task }

  /// Whether this task is a child task.
  public var isChildTask: Bool { bits & (1 << 24) != 0 }

  /// Whether this task has a future fragment.
  public var isFutureTask: Bool { bits & (1 << 25) != 0 }

  /// Whether this task is a task-group child.
  public var isGroupChildTask: Bool { bits & (1 << 26) != 0 }

  /// Whether this task implements an `async let`.
  public var isAsyncLetTask: Bool { bits & (1 << 28) != 0 }

  /// Whether this task has an initial task-executor preference.
  public var hasInitialTaskExecutorPreference: Bool { bits & (1 << 29) != 0 }

  /// Whether this task has an initial human-readable name.
  public var hasInitialTaskName: Bool { bits & (1 << 30) != 0 }
}

/// Flags for a Swift task group.
public struct TaskGroupFlags: Equatable, Sendable {
  /// Raw runtime flag bits.
  public let bits: UInt32

  /// Creates flags from their Swift runtime representation.
  public init(bits: UInt32) {
    self.bits = bits
  }

  /// Whether the group immediately releases completed tasks and disables
  /// result retrieval through `next()`.
  public var discardsResults: Bool { bits & (1 << 8) != 0 }
}

/// A kind of dynamic task-status record.
public enum TaskStatusRecordKind: UInt8, Sendable {
  case taskDependency = 0
  case childTask = 1
  case taskGroup = 2
  case cancellationNotification = 3
  case escalationNotification = 4
  case taskExecutorPreference = 5
  case taskName = 6
  case privateRecordLock = 192

  /// The first kind reserved for Swift runtime implementation records.
  public static let firstReserved = TaskStatusRecordKind.privateRecordLock
}

/// Flags stored at the start of a task-status record.
public struct TaskStatusRecordFlags: Equatable, Sendable {
  /// Raw runtime flag bits.
  public let bits: UInt

  /// Creates flags from their Swift runtime representation.
  public init(bits: UInt) {
    self.bits = bits
  }

  /// The status-record kind, or `nil` for a future runtime-defined kind.
  public var kind: TaskStatusRecordKind? {
    TaskStatusRecordKind(rawValue: UInt8(truncatingIfNeeded: bits))
  }
}

/// A kind of record passed while creating an asynchronous task.
public enum TaskOptionRecordKind: UInt8, Sendable {
  case initialSerialExecutor = 0
  case taskGroup = 1
  case asyncLetWithBuffer = 3
  case resultTypeInfo = 4
  case initialTaskExecutorUnowned = 5
  case initialTaskExecutorOwned = 6
  case initialTaskName = 7
  case runInline = 255
}

/// Flags stored at the start of a task-creation option record.
public struct TaskOptionRecordFlags: Equatable, Sendable {
  /// Raw runtime flag bits.
  public let bits: UInt

  /// Creates flags from their Swift runtime representation.
  public init(bits: UInt) {
    self.bits = bits
  }

  /// The option-record kind, or `nil` for a future runtime-defined kind.
  public var kind: TaskOptionRecordKind? {
    TaskOptionRecordKind(rawValue: UInt8(truncatingIfNeeded: bits))
  }
}

/// Flags supplied when initializing an async continuation.
public struct AsyncContinuationFlags: Equatable, Sendable {
  /// Raw runtime flag bits.
  public let bits: UInt

  /// Creates flags from their Swift runtime representation.
  public init(bits: UInt) {
    self.bits = bits
  }

  /// Whether the continuation may throw.
  public var canThrow: Bool { bits & (1 << 0) != 0 }

  /// Whether the continuation has an executor override.
  public var hasExecutorOverride: Bool { bits & (1 << 1) != 0 }

  /// Whether the continuation was pre-awaited.
  public var isPreawaited: Bool { bits & (1 << 2) != 0 }

  /// Whether resumption must force an executor switch.
  public var isExecutorSwitchForced: Bool { bits & (1 << 3) != 0 }
}

/// The lifecycle state of an async continuation.
public enum ContinuationStatus: UInt, Sendable {
  case pending = 0
  case awaited = 1
  case resumed = 2
}

/// An unmanaged reference to a serial executor.
///
/// This is the ABI representation used for actor and executor hops. Its
/// identity is not necessarily Swift reference-countable, so Echo treats it as
/// a borrowed raw address.
public struct SerialExecutorReference: Equatable {
  /// The executor identity, or `nil` for the generic executor.
  public let identity: UnsafeRawPointer?

  /// Raw implementation word, including the low-bit kind tag.
  public let implementation: UInt

  /// Creates a serial-executor reference from its runtime fields.
  public init(identity: UnsafeRawPointer?, implementation: UInt) {
    self.identity = identity
    self.implementation = implementation
  }

  /// Whether this is a generic executor reference.
  public var isGeneric: Bool { identity == nil }

  /// Whether this identifies a default actor executor.
  public var isDefaultActor: Bool { identity != nil && implementation == 0 }

  /// Whether this is the special executor used by `Task.immediate`.
  public var isSynchronousStart: Bool {
    identity == nil && kind == .immediate
  }

  /// The executor behavior tag, or `nil` for a future runtime-defined tag.
  public var kind: Kind? {
    Kind(rawValue: implementation & 0x7)
  }

  /// The masked serial-executor witness-table address, if this is a custom
  /// serial executor. Its entries remain runtime-private.
  public var witnessTable: UnsafeRawPointer? {
    guard isGeneric == false, isDefaultActor == false else { return nil }
    return UnsafeRawPointer(bitPattern: implementation & ~UInt(0x7))
  }
}

extension SerialExecutorReference {
  /// Behaviors tagged in the low bits of a serial-executor implementation.
  public enum Kind: UInt, Sendable {
    case ordinary = 0
    case complexEquality = 1
    case immediate = 2
  }
}

/// An unmanaged reference to a preferred task executor.
public struct TaskExecutorReference: Equatable {
  /// The task-executor identity, or `nil` when no preference is defined.
  public let identity: UnsafeRawPointer?

  /// Raw implementation word, including its low-bit kind tag.
  public let implementation: UInt

  /// Creates a task-executor reference from its runtime fields.
  public init(identity: UnsafeRawPointer?, implementation: UInt) {
    self.identity = identity
    self.implementation = implementation
  }

  /// Whether no task-executor preference is defined.
  public var isUndefined: Bool { identity == nil }

  /// Whether a task-executor preference is defined.
  public var isDefined: Bool { isUndefined == false }

  /// The executor behavior tag, or `nil` for a future runtime-defined tag.
  public var kind: Kind? {
    Kind(rawValue: implementation & 0x7)
  }

  /// The masked task-executor witness-table address, if defined. Its entries
  /// remain runtime-private.
  public var witnessTable: UnsafeRawPointer? {
    guard isDefined else { return nil }
    return UnsafeRawPointer(bitPattern: implementation & ~UInt(0x7))
  }
}

extension TaskExecutorReference {
  /// The only task-executor behavior currently defined by the Swift runtime.
  public enum Kind: UInt, Sendable {
    case ordinary = 0
  }
}
