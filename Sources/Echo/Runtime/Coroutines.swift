//
//  Coroutines.swift
//  Echo
//
//  Copyright © 2026 Echo contributors.
//

/// The allocation strategy used by a Swift coroutine frame.
public enum CoroutineAllocatorKind: UInt32, Sendable {
  /// The frame is allocated with `stacksave`/`stackrestore`.
  case stack = 0

  /// The frame is allocated by the async task allocator.
  case async = 1

  /// The frame is allocated with `malloc` and `free`.
  case malloc = 2

  /// The frame uses the runtime's typed malloc allocator.
  case typedMalloc = 3
}

/// Flags stored by a Swift coroutine allocator.
public struct CoroutineAllocatorFlags: Equatable, Sendable {
  /// Raw runtime flag bits.
  public let bits: UInt32

  /// Creates flags from their Swift runtime representation.
  public init(bits: UInt32) {
    self.bits = bits
  }

  /// The allocation strategy, or `nil` for a future runtime-defined kind.
  public var kind: CoroutineAllocatorKind? {
    CoroutineAllocatorKind(rawValue: bits & 0xFF)
  }

  /// Whether `swift_coro_dealloc` deallocates the frame immediately.
  public var shouldDeallocateImmediately: Bool {
    bits & (1 << 8) != 0
  }
}

/// A runtime-private coroutine allocator record.
///
/// Echo exposes its ABI fields for inspection only. The entry points use
/// runtime-private calling conventions and must not be invoked directly.
public struct CoroutineAllocator: LayoutWrapper {
  typealias Layout = _CoroutineAllocator

  /// Backing allocator record pointer.
  public let ptr: UnsafeRawPointer

  /// The allocator's flags.
  public var flags: CoroutineAllocatorFlags {
    layout._flags
  }

  /// The runtime-private allocation entry point.
  public var allocateFunction: UnsafeRawPointer? {
    layout._allocate
  }

  /// The runtime-private deallocation entry point.
  public var deallocateFunction: UnsafeRawPointer? {
    layout._deallocate
  }

  /// The runtime-private frame-allocation entry point.
  public var allocateFrameFunction: UnsafeRawPointer? {
    layout._allocateFrame
  }

  /// The runtime-private frame-deallocation entry point.
  public var deallocateFrameFunction: UnsafeRawPointer? {
    layout._deallocateFrame
  }
}

extension CoroutineAllocator: Equatable {}

struct _CoroutineAllocator {
  let _flags: CoroutineAllocatorFlags
  let _allocate: UnsafeRawPointer?
  let _deallocate: UnsafeRawPointer?
  let _allocateFrame: UnsafeRawPointer?
  let _deallocateFrame: UnsafeRawPointer?
}
