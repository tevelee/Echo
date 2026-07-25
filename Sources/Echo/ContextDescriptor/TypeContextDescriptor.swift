//
//  TypeContextDescriptor.swift
//  Echo
//
//  Created by Alejandro Alonso
//  Copyright © 2019 - 2021 Alejandro Alonso. All rights reserved.
//

/// A type context descriptor is a context descriptor who defines some new type.
/// This includes structs, classes, and enums. Protocols also define a new type,
/// but aren't considered type context descriptors.
///
/// ABI Stability: Stable since the following
///
///     | macOS | iOS/tvOS | watchOS | Linux | Windows |
///     |-------|----------|---------|-------|---------|
///     | 10.14 | 12.2     | 5.2     | NA    | NA      |
///
public protocol TypeContextDescriptor: ContextDescriptor {
  /// The flags that describe this type context descriptor.
  var typeFlags: TypeContextDescriptorFlags { get }
  
  /// The name of this type.
  var name: String { get }
  
  /// The metadata access function.
  var accessor: MetadataAccessFunction { get }
  
  /// The field descriptor that describes the stored representation of this
  /// type.
  var fields: FieldDescriptor { get }
  
  /// If this type has foreign metadata initialization, return it.
  var foreignMetadataInitialization: ForeignMetadataInitialization? { get }
  
  /// If this type has singleton metadata initialization, return it.
  var singletonMetadataInitialization: SingletonMetadataInitialization? { get }
}

extension TypeContextDescriptor {
  var _typeDescriptor: _TypeDescriptor {
    ptr.load(as: _TypeDescriptor.self)
  }
  
  /// The flags that describe this type context descriptor.
  public var typeFlags: TypeContextDescriptorFlags {
    TypeContextDescriptorFlags(bits: UInt64(flags.kindSpecificFlags))
  }
  
  /// The name of this type.
  public var name: String {
    let offset = ptr.offset(of: 2, as: Int32.self)
    let address = _typeDescriptor._name.address(from: offset)
    return address.string
  }
  
  /// The metadata access function.
  public var accessor: MetadataAccessFunction {
    let offset = ptr.offset(of: 3, as: Int32.self)
    let accessor = _typeDescriptor._accessor.address(from: offset)
    return MetadataAccessFunction(ptr: accessor)
  }
  
  /// Whether or not this type has a field descriptor.
  public var isReflectable: Bool {
    _typeDescriptor._fields.offset != 0
  }
  
  /// The field descriptor that describes the stored representation of this
  /// type.
  public var fields: FieldDescriptor {
    let offset = ptr.offset(of: 4, as: Int32.self)
    let address = _typeDescriptor._fields.address(from: offset)
    return FieldDescriptor(ptr: address)
  }
  
  /// The generic context that is unique to type context descriptors.
  public var typeGenericContext: TypeGenericContext {
    TypeGenericContext(ptr: ptr + genericContextOffset)
  }
}

/// Structure that contains the completion function for initializing singleton
/// foreign metadata.
public struct ForeignMetadataInitialization: LayoutWrapper {
  typealias Layout = _ForeignMetadataInitialization
  
  /// Backing ForeignMetadataInitialzation pointer.
  let ptr: UnsafeRawPointer

  /// The runtime-private function that completes this metadata initialization,
  /// if one was emitted. It is exposed for inspection only and must not be
  /// invoked by clients.
  public var completionFunction: UnsafeRawPointer? {
    let field = ptr + MemoryLayout<_ForeignMetadataInitialization>.offset(
      of: \._completionFunc
    )!
    let reference = layout._completionFunc
    guard reference.isNull == false else { return nil }
    return reference.address(from: field)
  }
}

/// Structure that contains information needed to perform initialization of
/// singleton value metadata.
public struct SingletonMetadataInitialization: LayoutWrapper {
  typealias Layout = _SingletonMetadataInitialization
  
  /// Backing SingletonMetadataInitialization pointer.
  let ptr: UnsafeRawPointer

  /// The runtime-owned mutable initialization cache, if the compiler emitted
  /// one. Its contents are intentionally not decoded or mutated by Echo.
  public var initializationCache: UnsafeRawPointer? {
    let field = ptr + MemoryLayout<_SingletonMetadataInitialization>.offset(
      of: \._initializationCache
    )!
    let reference = layout._initializationCache
    guard reference.isNull == false else { return nil }
    return reference.address(from: field)
  }

  /// The union target used by this record. It is incomplete metadata for value
  /// types and classes without resilient ancestry, or a resilient class
  /// metadata pattern for classes with resilient ancestry.
  public var initialMetadataOrResilientPattern: UnsafeRawPointer? {
    let field = ptr + MemoryLayout<_SingletonMetadataInitialization>.offset(
      of: \._incompleteMetadataOrResilientPattern
    )!
    let reference = RelativeDirectPointer<Void>(
      offset: layout._incompleteMetadataOrResilientPattern
    )
    guard reference.isNull == false else { return nil }
    return reference.address(from: field)
  }

  /// The runtime-private function that completes this metadata initialization.
  /// It is exposed for inspection only and must not be invoked by clients.
  public var completionFunction: UnsafeRawPointer? {
    let field = ptr + MemoryLayout<_SingletonMetadataInitialization>.offset(
      of: \._completionFunc
    )!
    let reference = layout._completionFunc
    guard reference.isNull == false else { return nil }
    return reference.address(from: field)
  }
}

/// The allocation pattern used by a non-generic class with resilient ancestry.
public struct ResilientClassMetadataPattern: LayoutWrapper {
  typealias Layout = _ResilientClassMetadataPattern

  /// Backing resilient class metadata pattern pointer.
  let ptr: UnsafeRawPointer

  /// The runtime-private allocation entry point, if the runtime should not use
  /// its built-in class metadata relocator. It is exposed for inspection only.
  public var relocationFunction: UnsafeRawPointer? {
    functionAddress(for: \._relocationFunction)
  }

  /// The runtime-private heap-destroyer entry point. It is exposed for
  /// inspection only and must not be invoked by clients.
  public var destroyFunction: UnsafeRawPointer? {
    functionAddress(for: \._destroy)
  }

  /// The runtime-private instance-variable destroyer entry point, if one was
  /// emitted. It is exposed for inspection only and must not be invoked by
  /// clients.
  public var ivarDestroyer: UnsafeRawPointer? {
    functionAddress(for: \._ivarDestroyer)
  }

  /// Class flags applied to metadata allocated from this pattern.
  public var flags: ClassMetadata.Flags {
    layout._flags
  }

  /// The Objective-C class RO-data record, if one is present on this runtime.
  public var data: UnsafeRawPointer? {
    relativeAddress(for: \._data)
  }

  /// The Objective-C metaclass record, if one is present on this runtime.
  public var metaclass: UnsafeRawPointer? {
    relativeAddress(for: \._metaclass)
  }

  private func functionAddress(
    for field: KeyPath<_ResilientClassMetadataPattern, RelativeDirectPointer<UnsafeRawPointer>>
  ) -> UnsafeRawPointer? {
    relativeAddress(for: field)
  }

  private func relativeAddress<T>(
    for field: KeyPath<_ResilientClassMetadataPattern, RelativeDirectPointer<T>>
  ) -> UnsafeRawPointer? {
    let address = ptr + MemoryLayout<_ResilientClassMetadataPattern>.offset(of: field)!
    let reference = layout[keyPath: field]
    guard reference.isNull == false else { return nil }
    return reference.address(from: address)
  }
}

struct _TypeDescriptor {
  let _base: _ContextDescriptor
  let _name: RelativeDirectPointer<CChar>
  let _accessor: RelativeDirectPointer<UnsafeRawPointer>
  let _fields: RelativeDirectPointer<_FieldDescriptor>
}

struct _ForeignMetadataInitialization {
  let _completionFunc: RelativeDirectPointer<UnsafeRawPointer>
}

struct _SingletonMetadataInitialization {
  let _initializationCache: RelativeDirectPointer<Void>
  
  // This is either a relative direct pointer to some incomplete metadata, or
  // a relative direct pointer to some resilent class metadata pattern.
  let _incompleteMetadataOrResilientPattern: Int32
  
  let _completionFunc: RelativeDirectPointer<UnsafeRawPointer>
}

struct _ResilientClassMetadataPattern {
  let _relocationFunction: RelativeDirectPointer<UnsafeRawPointer>
  let _destroy: RelativeDirectPointer<UnsafeRawPointer>
  let _ivarDestroyer: RelativeDirectPointer<UnsafeRawPointer>
  let _flags: ClassMetadata.Flags
  let _data: RelativeDirectPointer<Void>
  let _metaclass: RelativeDirectPointer<Void>
}
