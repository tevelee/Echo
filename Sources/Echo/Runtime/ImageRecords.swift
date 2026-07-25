//
//  ImageRecords.swift
//  Echo
//
//  Copyright © 2026 Tevelee
//

/// A scope containing the dynamic replacements an image registers together.
///
/// The scope is descriptive only. Echo never enables or disables replacements;
/// the Swift runtime owns those operations and their synchronization.
public struct DynamicReplacementScope: LayoutWrapper {
  typealias Layout = _DynamicReplacementScope

  let ptr: UnsafeRawPointer

  /// Reserved runtime flags for this replacement scope.
  public var flags: UInt32 {
    layout._flags
  }

  /// The replacement descriptors registered by this scope.
  public var replacementDescriptors: [DynamicReplacementDescriptor] {
    Array(unsafeUninitializedCapacity: Int(layout._numReplacements)) {
      for index in 0 ..< Int(layout._numReplacements) {
        $0[index] = DynamicReplacementDescriptor(
          ptr: trailing.advanced(
            by: index * MemoryLayout<_DynamicReplacementDescriptor>.stride
          )
        )
      }
      $1 = Int(layout._numReplacements)
    }
  }
}

/// One function replacement recorded in a dynamic replacement scope.
public struct DynamicReplacementDescriptor: LayoutWrapper {
  typealias Layout = _DynamicReplacementDescriptor

  let ptr: UnsafeRawPointer

  /// The key for the function being replaced, if the image records one.
  public var replacedFunctionKey: DynamicReplacementKey? {
    let reference = layout._replacedFunctionKey
    guard reference.isNull == false else { return nil }

    let pointer = address(for: \._replacedFunctionKey)
    #if _ptrauth(_arm64e)
    guard let pointer = __ptrauth_strip_asda(pointer) else { return nil }
    #endif
    return DynamicReplacementKey(ptr: pointer)
  }

  /// The replacement implementation entry point.
  ///
  /// Its calling convention depends on `replacedFunctionKey`; Echo exposes the
  /// address for inspection and does not invoke it.
  public var replacementFunction: UnsafeRawPointer {
    address(for: \._replacementFunction)
  }

  /// The replacement-chain entry managed by the Swift runtime.
  public var chainEntry: DynamicReplacementChainEntry {
    DynamicReplacementChainEntry(
      ptr: address(for: \._chainEntry)
    )
  }

  /// Whether the runtime keeps the previous replacement in the call chain.
  public var shouldChain: Bool {
    layout._flags & 0x1 != 0
  }
}

/// The dynamic-replacement key for one function or accessor.
public struct DynamicReplacementKey: LayoutWrapper {
  typealias Layout = _DynamicReplacementKey

  let ptr: UnsafeRawPointer

  /// The root entry of the replacement chain.
  public var root: DynamicReplacementChainEntry? {
    guard layout._root.isNull == false else { return nil }
    return DynamicReplacementChainEntry(ptr: address(for: \._root))
  }

  /// The low sixteen-bit discriminator used by the runtime for this key.
  public var extraDiscriminator: UInt16 {
    UInt16(truncatingIfNeeded: layout._flags)
  }

  /// Whether this replacement has an asynchronous entry point.
  public var isAsync: Bool {
    layout._flags & (1 << 16) != 0
  }

  /// Whether this replacement uses a callee-allocated coroutine entry point.
  public var isCalleeAllocatedCoroutine: Bool {
    layout._flags & (1 << 17) != 0
  }

  /// Whether this key represents data rather than a synchronous function.
  public var isData: Bool {
    isAsync || isCalleeAllocatedCoroutine
  }
}

/// An entry in a dynamic replacement chain.
public struct DynamicReplacementChainEntry: LayoutWrapper {
  typealias Layout = _DynamicReplacementChainEntry

  let ptr: UnsafeRawPointer

  /// The implementation currently stored in this entry.
  ///
  /// The runtime may authenticate this pointer before calling it. Echo exposes
  /// it for inspection only.
  public var implementationFunction: UnsafeRawPointer? {
    layout._implementationFunction
  }

  /// The next entry in this replacement chain, if any.
  public var next: DynamicReplacementChainEntry? {
    guard let pointer = layout._next else { return nil }
    return DynamicReplacementChainEntry(ptr: pointer)
  }
}

/// A replacement of one opaque (`some`) type descriptor by another.
public struct OpaqueTypeReplacement: LayoutWrapper {
  typealias Layout = _OpaqueTypeReplacement

  let ptr: UnsafeRawPointer

  /// The opaque descriptor replaced by the image.
  public var original: OpaqueDescriptor? {
    let reference = layout._original
    guard reference.isNull == false else { return nil }
    return getContextDescriptor(at: address(for: \._original)) as? OpaqueDescriptor
  }

  /// The opaque descriptor installed as the replacement.
  public var replacement: OpaqueDescriptor? {
    let reference = layout._replacement
    guard reference.isNull == false else { return nil }
    return getContextDescriptor(at: address(for: \._replacement)) as? OpaqueDescriptor
  }
}

/// A function record that the Swift runtime can locate by its mangled name.
///
/// The entry point is fully abstracted and may be synchronous, asynchronous,
/// or a distributed-actor accessor. Echo exposes the record but does not call
/// it because constructing its arguments is runtime-specific.
public struct AccessibleFunction: LayoutWrapper {
  typealias Layout = _AccessibleFunction

  let ptr: UnsafeRawPointer

  /// The symbolic Swift mangling that identifies this function.
  public var mangledName: UnsafeRawPointer {
    address(for: \._mangledName)
  }

  /// The byte length of `mangledName`, including symbolic-reference payloads.
  public var mangledNameLength: Int {
    getSymbolicMangledNameLength(mangledName)
  }

  /// The generic environment needed to construct this function's arguments.
  public var genericEnvironment: GenericEnvironment? {
    guard layout._genericEnvironment.isNull == false else { return nil }
    return GenericEnvironment(ptr: address(for: \._genericEnvironment))
  }

  /// The symbolic mangling of the function's fully abstracted type.
  public var mangledType: UnsafeRawPointer {
    address(for: \._mangledType)
  }

  /// The byte length of `mangledType`, including symbolic-reference payloads.
  public var mangledTypeLength: Int {
    getSymbolicMangledNameLength(mangledType)
  }

  /// The fully abstracted function entry point. Echo does not invoke it.
  public var function: UnsafeRawPointer {
    address(for: \._function)
  }

  /// Flags describing this record.
  public var flags: AccessibleFunctionFlags {
    layout._flags
  }
}

/// Flags stored in an accessible-function record.
public struct AccessibleFunctionFlags {
  /// Flags as represented in bits.
  public let bits: UInt32

  /// Whether this record represents a distributed actor function.
  public var isDistributed: Bool {
    bits & 0x1 != 0
  }
}

/// The generic signature data associated with an accessible function.
public struct GenericEnvironment: LayoutWrapper {
  typealias Layout = GenericEnvironmentFlags

  let ptr: UnsafeRawPointer

  /// Flags describing the generic-environment record.
  public var flags: GenericEnvironmentFlags {
    layout
  }

  /// Cumulative generic-parameter counts for each nesting level.
  public var genericParameterCounts: [UInt16] {
    loadTrailing(count: flags.numGenericParameterLevels, as: UInt16.self)
  }

  /// Generic parameters in this environment.
  public var genericParameters: [GenericParameterDescriptor] {
    guard let count = genericParameterCounts.last else { return [] }
    let offset = flags.numGenericParameterLevels * MemoryLayout<UInt16>.stride
    return loadTrailing(
      from: offset,
      count: Int(count),
      as: GenericParameterDescriptor.self
    )
  }

  /// Generic requirements in this environment.
  public var requirements: [GenericRequirementDescriptor] {
    let parametersOffset = flags.numGenericParameterLevels * MemoryLayout<UInt16>.stride
    let parametersSize = (genericParameterCounts.last.map(Int.init) ?? 0)
      * MemoryLayout<GenericParameterDescriptor>.stride
    let requirementsOffset = aligned(
      parametersOffset + parametersSize,
      to: MemoryLayout<_GenericRequirementDescriptor>.alignment
    )

    return Array(unsafeUninitializedCapacity: flags.numGenericRequirements) {
      for index in 0 ..< flags.numGenericRequirements {
        $0[index] = GenericRequirementDescriptor(
          ptr: (trailing + requirementsOffset).advanced(
            by: index * MemoryLayout<_GenericRequirementDescriptor>.stride
          )
        )
      }
      $1 = flags.numGenericRequirements
    }
  }

  private func loadTrailing<T>(count: Int, as: T.Type) -> [T] {
    loadTrailing(from: 0, count: count, as: T.self)
  }

  private func loadTrailing<T>(from offset: Int, count: Int, as: T.Type) -> [T] {
    Array(unsafeUninitializedCapacity: count) {
      for index in 0 ..< count {
        $0[index] = (trailing + offset).load(
          fromByteOffset: index * MemoryLayout<T>.stride,
          as: T.self
        )
      }
      $1 = count
    }
  }

  private func aligned(_ offset: Int, to alignment: Int) -> Int {
    (offset + alignment - 1) & -alignment
  }
}

/// Flags stored in a generic-environment descriptor.
public struct GenericEnvironmentFlags {
  /// Flags as represented in bits.
  public let bits: UInt32

  /// Number of generic nesting levels represented by the record.
  public var numGenericParameterLevels: Int {
    Int(bits & 0xFFF)
  }

  /// Number of generic requirements represented by the record.
  public var numGenericRequirements: Int {
    Int((bits >> 12) & 0xFFFF)
  }
}

struct _DynamicReplacementScope {
  let _flags: UInt32
  let _numReplacements: UInt32
}

struct _DynamicReplacementDescriptor {
  let _replacedFunctionKey: RelativeIndirectablePointer<_DynamicReplacementKey>
  let _replacementFunction: RelativeDirectPointer<Void>
  let _chainEntry: RelativeDirectPointer<Void>
  let _flags: UInt32
}

struct _DynamicReplacementKey {
  let _root: RelativeDirectPointer<_DynamicReplacementChainEntry>
  let _flags: UInt32
}

struct _DynamicReplacementChainEntry {
  let _implementationFunction: UnsafeRawPointer?
  let _next: UnsafeRawPointer?
}

struct _OpaqueTypeReplacement {
  let _original: RelativeIndirectablePointer<_OpaqueDescriptor>
  let _replacement: RelativeDirectPointer<_OpaqueDescriptor>
}

struct _AccessibleFunction {
  let _mangledName: RelativeDirectPointer<CChar>
  let _genericEnvironment: RelativeDirectPointer<GenericEnvironmentFlags>
  let _mangledType: RelativeDirectPointer<CChar>
  let _function: RelativeDirectPointer<Void>
  let _flags: AccessibleFunctionFlags
}
