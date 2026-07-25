//
//  TypeMetadata.swift
//  Echo
//
//  Created by Alejandro Alonso
//  Copyright © 2019 - 2021 Alejandro Alonso. All rights reserved.
//

import Foundation

#if _ptrauth(_arm64e)
import CEcho
#endif

/// Type metadata refers to those metadata records who declare a new type in
/// Swift. Said metadata records only refer to structs, classes, and enums.
///
/// ABI Stability: Stable since the following
///
///     | macOS | iOS/tvOS | watchOS | Linux | Windows |
///     |-------|----------|---------|-------|---------|
///     | 10.14 | 12.2     | 5.2     | NA    | NA      |
///
public protocol TypeMetadata: Metadata {}

/// The allocation lifetime encoded in a runtime metadata or witness-table
/// pack pointer.
///
/// Stack-backed packs have no count stored with their element pointer. They
/// are intentionally not enumerated by Echo because the compiler owns the
/// corresponding pack-length argument and its storage lifetime.
public enum PackLifetime: Equatable, Sendable {
  /// The pack elements belong to the caller's stack frame.
  case onStack

  /// The pack owns a heap allocation whose preceding word stores its count.
  case onHeap
}

/// A runtime pack of type metadata used by variadic generic expansions.
///
/// The Swift ABI uses the low bit of `taggedPointer` to distinguish
/// heap-backed packs from packs borrowed from the stack. Only heap-backed
/// packs can be enumerated: their element count is stored one word before the
/// element pointer.
public struct MetadataPack {
  /// The ABI pointer including its low-bit lifetime tag.
  public let taggedPointer: UnsafeRawPointer

  /// Creates a pack view for an ABI pointer from a generic argument layout.
  public init(taggedPointer: UnsafeRawPointer) {
    self.taggedPointer = taggedPointer
  }

  /// Whether the elements are backed by the stack or a heap allocation.
  public var lifetime: PackLifetime {
    UInt(bitPattern: taggedPointer) & 1 == 0 ? .onStack : .onHeap
  }

  /// The untagged address of the first metadata element.
  public var elementsPointer: UnsafeRawPointer {
    UnsafeRawPointer(bitPattern: UInt(bitPattern: taggedPointer) & ~UInt(1))!
  }

  /// The number of elements when the runtime allocated the pack on the heap.
  ///
  /// Stack-backed packs do not carry their count and return `nil`.
  public var count: Int? {
    guard lifetime == .onHeap else { return nil }
    let rawCount = elementsPointer.offset(of: -1).load(as: UInt.self)
    return Int(exactly: rawCount)
  }

  /// Metadata for every element of a heap-backed pack.
  ///
  /// Stack-backed packs return an empty array rather than reading a count from
  /// memory the ABI deliberately leaves unspecified.
  public var elements: [Metadata] {
    guard let count else { return [] }

    return (0 ..< count).map { index in
      let pointer = elementsPointer.load(
        fromByteOffset: index * MemoryLayout<UnsafeRawPointer>.stride,
        as: UnsafeRawPointer.self
      )
      return getMetadata(at: pointer)
    }
  }
}

/// A runtime pack of protocol witness tables used by variadic generic
/// expansions.
///
/// As with `MetadataPack`, only heap-backed packs can be safely enumerated.
public struct WitnessTablePack {
  /// The ABI pointer including its low-bit lifetime tag.
  public let taggedPointer: UnsafeRawPointer

  /// Creates a pack view for an ABI pointer from a generic argument layout.
  public init(taggedPointer: UnsafeRawPointer) {
    self.taggedPointer = taggedPointer
  }

  /// Whether the elements are backed by the stack or a heap allocation.
  public var lifetime: PackLifetime {
    UInt(bitPattern: taggedPointer) & 1 == 0 ? .onStack : .onHeap
  }

  /// The untagged address of the first witness-table element.
  public var elementsPointer: UnsafeRawPointer {
    UnsafeRawPointer(bitPattern: UInt(bitPattern: taggedPointer) & ~UInt(1))!
  }

  /// The number of elements when the runtime allocated the pack on the heap.
  ///
  /// Stack-backed packs do not carry their count and return `nil`.
  public var count: Int? {
    guard lifetime == .onHeap else { return nil }
    let rawCount = elementsPointer.offset(of: -1).load(as: UInt.self)
    return Int(exactly: rawCount)
  }

  /// Witness tables for every element of a heap-backed pack.
  ///
  /// Stack-backed packs return an empty array rather than reading a count from
  /// memory the ABI deliberately leaves unspecified.
  public var elements: [WitnessTable] {
    guard let count else { return [] }

    return (0 ..< count).map { index in
      WitnessTable(ptr: elementsPointer.load(
        fromByteOffset: index * MemoryLayout<UnsafeRawPointer>.stride,
        as: UnsafeRawPointer.self
      ))
    }
  }
}

/// One word in a generic metadata argument layout.
///
/// Swift 6 generic layouts can contain packs and value arguments in addition
/// to ordinary type metadata and witness tables. The cases preserve that ABI
/// distinction rather than interpreting every word as an `Any.Type`.
public enum GenericArgument {
  /// The runtime length of a type-parameter pack.
  case packLength(Int)

  /// Metadata for an ordinary type parameter.
  case metadata(Any.Type)

  /// A pointer to a runtime metadata pack.
  case metadataPack(UnsafeRawPointer)

  /// A witness table for an ordinary protocol requirement.
  case witnessTable(WitnessTable)

  /// A pointer to a runtime witness-table pack.
  case witnessTablePack(UnsafeRawPointer)

  /// A raw value argument. Its representation is described by the generic
  /// context's `GenericValueDescriptor` records.
  case value(UInt)

  var abiWord: UInt {
    switch self {
    case let .packLength(length):
      return UInt(bitPattern: length)
    case let .metadata(type):
      return UInt(bitPattern: unsafeBitCast(type, to: UnsafeRawPointer.self))
    case let .metadataPack(pointer), let .witnessTablePack(pointer):
      return UInt(bitPattern: pointer)
    case let .witnessTable(table):
      return UInt(bitPattern: table.ptr)
    case let .value(value):
      return value
    }
  }

  /// A typed view of this metadata-pack argument, if it is one.
  public var metadataPackValue: MetadataPack? {
    guard case let .metadataPack(pointer) = self else { return nil }
    return MetadataPack(taggedPointer: pointer)
  }

  /// A typed view of this witness-table-pack argument, if it is one.
  public var witnessTablePackValue: WitnessTablePack? {
    guard case let .witnessTablePack(pointer) = self else { return nil }
    return WitnessTablePack(taggedPointer: pointer)
  }
}

extension TypeMetadata {
  /// The compiler-emitted compact layout-string encoding for this nominal
  /// type, if the descriptor advertises one. The encoding is runtime-private
  /// data and is exposed for inspection only.
  public var layoutString: UnsafeRawPointer? {
    guard contextDescriptor?.typeFlags.hasLayoutString == true else {
      return nil
    }

    let pointer = ptr.offset(of: -2).load(as: UnsafeRawPointer?.self)
    #if _ptrauth(_arm64e)
    return __ptrauth_strip_asda(pointer)
    #else
    return pointer
    #endif
  }

  /// The list of conformances defined for this type metadata.
  ///
  /// NOTE: This list is populated once before the program starts with all of
  ///       the conformances that are statically know at compile time. If you
  ///       are attempting to load libraries dynamically at runtime, this list
  ///       will update automatically, so make sure if you need up to date
  ///       information on a type's conformances, fetch this often. Example:
  ///
  ///       let metadata = ...
  ///       var conformances = metadata.conformances
  ///       loadPlugin(...)
  ///       // conformances is now outdated! Refresh it by calling this again.
  ///       conformances = metadata.conformances
  public var conformances: [ConformanceDescriptor] {
    refreshLoadedImages()
    
    guard let contextDescriptorPtr = contextDescriptor?.ptr else {
        return []
    }
    
    return imageInspectionStorage.conformances(for: contextDescriptorPtr)
  }
  
  /// The base type context descriptor for this type metadata record.
  public var contextDescriptor: TypeContextDescriptor? {
    switch self {
    case let structMetadata as StructMetadata:
      return structMetadata.descriptor
    case let enumMetadata as EnumMetadata:
      return enumMetadata.descriptor
    case let classMetadata as ClassMetadata:
      return classMetadata.descriptor
    default:
      fatalError("Unknown TypeMetadata conformance")
    }
  }
  
  /// An array of field offsets for this type's stored representation.
  public var fieldOffsets: [Int] {
    switch self {
    case let structMetadata as StructMetadata:
      return structMetadata.fieldOffsets
    case let classMetadata as ClassMetadata:
      return classMetadata.fieldOffsets
    case is EnumMetadata:
      return []
    default:
      fatalError("Unknown TypeMetadata conformance")
    }
  }
  
  var genericArgumentPtr: UnsafeRawPointer? {
    switch self {
    case is StructMetadata:
      return ptr + MemoryLayout<_StructMetadata>.size
      
    case is EnumMetadata:
      return ptr + MemoryLayout<_EnumMetadata>.size
      
    case let classMetadata as ClassMetadata:
      guard let descriptor = classMetadata.descriptor else {
        return nil
      }
      return ptr.offset(of: descriptor.genericArgumentOffset)
      
    default:
      fatalError("Unknown TypeMetadata conformance")
    }
  }
  
  /// The generic argument layout for this type.
  ///
  /// The result includes pack lengths, metadata packs, witness-table packs,
  /// and value arguments when the context uses them. Unknown future argument
  /// forms fail closed as an empty result instead of being reinterpreted as a
  /// metatype.
  public var genericArguments: [GenericArgument] {
    guard let contextDescriptor = contextDescriptor,
          contextDescriptor.flags.isGeneric,
          // Explicitly only call this once because class metadata could require
          // computation, so only do it once if needed.
          let gap = genericArgumentPtr,
          let context = contextDescriptor.genericContext else {
      return []
    }

    var offset = 0
    var arguments = [GenericArgument]()

    func word() -> UInt {
      defer { offset += 1 }
      return gap.load(
        fromByteOffset: offset * MemoryLayout<UInt>.stride,
        as: UInt.self
      )
    }

    // Pack lengths are stored before all parameter metadata.
    for parameter in context.parameters
    where parameter.kind == .typePack && parameter.hasKeyArgument {
      let length = Int(bitPattern: word())
      guard length >= 0 else { return [] }
      arguments.append(.packLength(length))
    }

    for parameter in context.parameters where parameter.hasKeyArgument {
      switch parameter.kind {
      case .type:
        arguments.append(.metadata(unsafeBitCast(word(), to: Any.Type.self)))
      case .typePack:
        guard let pointer = UnsafeRawPointer(bitPattern: word()) else { return [] }
        arguments.append(.metadataPack(pointer))
      case .value:
        arguments.append(.value(word()))
      }
    }

    for requirement in context.requirements where requirement.flags.hasKeyArgument {
      guard requirement.flags.kind == .protocol else { return [] }
      guard let pointer = UnsafeRawPointer(bitPattern: word()) else { return [] }

      if requirement.flags.isPackRequirement {
        arguments.append(.witnessTablePack(pointer))
      } else {
        arguments.append(.witnessTable(WitnessTable(ptr: pointer)))
      }
    }

    guard offset == context.numKeyArguments else { return [] }
    return arguments
  }

  /// The ordinary type arguments for a type-only generic context.
  ///
  /// This compatibility convenience deliberately returns an empty array for
  /// packs, values, non-key parameters, or unknown layouts. Use
  /// `genericArguments` for all modern generic contexts.
  public var genericTypes: [Any.Type] {
    guard let context = contextDescriptor?.genericContext,
          context.parameters.allSatisfy({
            $0.kind == .type && $0.hasKeyArgument
          })
    else { return [] }

    let arguments = genericArguments
    guard arguments.count >= context.numParams else { return [] }

    let types = arguments.prefix(context.numParams).compactMap { argument -> Any.Type? in
      guard case let .metadata(type) = argument else { return nil }
      return type
    }

    guard types.count == context.numParams else { return [] }
    return types
  }
  
  /// An array of metadata records for the types that represent the generic
  /// arguments that make up this type.
  public var genericMetadata: [Metadata] {
    genericTypes.map { reflect($0) }
  }
  
  /// Given a mangled type name to some field, superclass, etc., return the
  /// type. Using this is the preferred way to interact with mangled type names
  /// because this uses the metadata's generic context and arguments and such to
  /// fill in generic types along with caching the mangled name for future use.
  /// - Parameter mangledName: The mangled type name pointer to some type in
  ///                          this metadata's reach.
  /// - Returns: The type that the mangled type name refers to, if we're able
  ///            to demangle it.
  public func type(
    of mangledName: UnsafeRawPointer
  ) -> Any.Type? {
    let entry = mangledNameCache.value(for: mangledName)
    
    if entry != nil {
      return entry!
    }
    
    guard let contextDescriptor = contextDescriptor else {
      return nil
    }
    
    let length = getSymbolicMangledNameLength(mangledName)
    let name = mangledName.assumingMemoryBound(to: UInt8.self)
    let type = _getTypeByMangledNameInContext(
      name,
      UInt(length),
      genericContext: contextDescriptor.ptr,
      genericArguments: genericArgumentPtr
    )
    
    mangledNameCache.insert(type, for: mangledName)
    
    return type
  }
}

/// Caches resolved symbolic names behind a lock because metadata queries can
/// be initiated concurrently by the runtime.
private final class MangledNameCache: @unchecked Sendable {
  private let lock = NSLock()
  private var values = [UnsafeRawPointer: Any.Type?]()

  func value(for mangledName: UnsafeRawPointer) -> Any.Type? {
    lock.withLock {
      values[mangledName] ?? nil
    }
  }

  func insert(_ type: Any.Type?, for mangledName: UnsafeRawPointer) {
    lock.withLock {
      values[mangledName] = type
    }
  }
}

private let mangledNameCache = MangledNameCache()
