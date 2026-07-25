//
//  ClassDescriptor.swift
//  Echo
//
//  Created by Alejandro Alonso
//  Copyright © 2019 - 2021 Alejandro Alonso. All rights reserved.
//

import Atomics

#if canImport(ObjectiveC)
import ObjectiveC
import CEcho
#endif

/// A class descriptor that descibes some class context.
///
/// ABI Stability: Stable since the following
///
///     | macOS | iOS/tvOS | watchOS | Linux | Windows |
///     |-------|----------|---------|-------|---------|
///     | 10.14 | 12.2     | 5.2     | NA    | NA      |
///
public struct ClassDescriptor: TypeContextDescriptor, LayoutWrapper {
  typealias Layout = _ClassDescriptor
  
  /// Backing context descriptor pointer.
  public let ptr: UnsafeRawPointer
  
  /// The mangled type name for this class's superclass, if it has one.
  public var superclass: UnsafeRawPointer {
    address(for: \._superclass)
  }
  
  /// The negative size of the metadata objects in this class.
  public var negativeSize: Int {
    assert(!typeFlags.classHasResilientSuperclass)
    return Int(layout._negativeSizeOrResilientBounds)
  }
  
  /// The resilient bounds for this class.
  var resilientBounds: StoredClassMetadataBounds {
    let start = address(for: \._negativeSizeOrResilientBounds)
    let address = start.relativeDirectAddress(
      as: _StoredClassMetadataBounds.self
    )
    return StoredClassMetadataBounds(ptr: address)
  }
  
  /// The positive size of the metadata objects in this class.
  public var positiveSize: Int {
    assert(!typeFlags.classHasResilientSuperclass)
    return Int(layout._positiveSizeOrExtraFlags)
  }
  
  /// The number of members this class defines. This is both properties and
  /// methods.
  public var numMembers: Int {
    Int(layout._numImmediateMembers)
  }
  
  /// The number of properties this class declares (not including superclass)
  /// properties).
  public var numFields: Int {
    Int(layout._numFields)
  }
  
  /// The number of words away the field offset vector is from canonical
  /// metadata pointer.
  public var fieldOffsetVectorOffset: Int {
    guard typeFlags.classHasResilientSuperclass else {
      return Int(layout._fieldOffsetVectorOffset)
    }
    
    // Load the immediate members offset as seq_cst. I'm unsure if this is the
    // correct memory order that was intended, but currently in Metadata.h in
    // the Swift repository there is an implicit one used in
    // `getFieldOffsetVectorOffset`. There is no explicit memory order load, so
    // by default C++ chooses seq_cst for arithmetic operations. Be consistent
    // with what the Swift runtime is currently doing.
    
    // The memory is already initialized from the binary, here we're simply
    // binding the type from Swift's perspective. AFAICT, there is no way to
    // just unbind a type from memory without deinitializing it as well (which
    // we don't want to do).
    let atomicIntPtr = resilientBounds.ptr.mutable.bindMemory(
      to: UnsafeAtomic<Int>.Storage.self,
      capacity: 1
    )
    
    let immediateMembersOffset = UnsafeAtomic<Int>.Storage.atomicLoad(
      at: atomicIntPtr,
      ordering: .sequentiallyConsistent
    )
    
    return immediateMembersOffset / MemoryLayout<Int>.size
            + Int(layout._fieldOffsetVectorOffset)
  }
  
  /// A pointer to the resilient superclass. This pointer differs in type
  /// depending on what typeFlags.resilientSuperclassRefKind returns.
  public var resilientSuperclass: UnsafeRawPointer? {
    guard let offset = trailingLayout.resilientSuperclass else { return nil }
    let field = trailing + offset
    let reference = field.load(as: RelativeDirectPointer<Void>.self)
    guard reference.isNull == false else { return nil }
    return reference.address(from: field)
  }
  
  /// The foreign metadata initialization info for this class metadata, if it
  /// has any.
  public var foreignMetadataInitialization: ForeignMetadataInitialization? {
    guard let offset = trailingLayout.foreignMetadataInitialization else { return nil }
    return ForeignMetadataInitialization(ptr: trailing + offset)
  }
  
  /// The singleton metadata initialization info for this class metadata, if it
  /// has any.
  public var singletonMetadataInitialization: SingletonMetadataInitialization? {
    guard let offset = trailingLayout.singletonMetadataInitialization else { return nil }
    return SingletonMetadataInitialization(ptr: trailing + offset)
  }
  
  /// The VTable header information for this class, if it has a vtable.
  public var vtableHeader: VTableDescriptorHeader? {
    guard let offset = trailingLayout.vtableHeader else { return nil }
    return VTableDescriptorHeader(ptr: trailing + offset)
  }
  
  /// An array of all of the method descriptors for this class for the entries
  /// in the vtable, if this class has a vtable.
  public var methodDescriptors: [MethodDescriptor] {
    guard let offset = trailingLayout.methodDescriptors else { return [] }
    return Array(unsafeUninitializedCapacity: trailingLayout.numMethodDescriptors) {
      for i in 0 ..< trailingLayout.numMethodDescriptors {
        $0[i] = MethodDescriptor(
          ptr: (trailing + offset).advanced(
            by: i * MemoryLayout<_MethodDescriptor>.stride
          )
        )
      }
      $1 = trailingLayout.numMethodDescriptors
    }
  }
  
  /// The override table header indicating how many method overrides there are
  /// for this class, if it has an override table.
  public var overrideTableHeader: OverrideTableHeader? {
    guard let offset = trailingLayout.overrideTableHeader else { return nil }
    return OverrideTableHeader(ptr: trailing + offset)
  }
  
  /// An array of all of the method override descriptors, if this class has an
  /// override table.
  public var methodOverrideDescriptors: [MethodOverrideDescriptor] {
    guard let offset = trailingLayout.methodOverrideDescriptors else { return [] }
    return Array(unsafeUninitializedCapacity: trailingLayout.numMethodOverrideDescriptors) {
      for i in 0 ..< trailingLayout.numMethodOverrideDescriptors {
        $0[i] = MethodOverrideDescriptor(
          ptr: (trailing + offset).advanced(
            by: i * MemoryLayout<_MethodOverrideDescriptor>.stride
          )
        )
      }
      $1 = trailingLayout.numMethodOverrideDescriptors
    }
  }

  /// Extra class flags stored when this class has a resilient superclass.
  public var extraClassFlags: ExtraClassDescriptorFlags? {
    guard typeFlags.classHasResilientSuperclass else { return nil }
    return ExtraClassDescriptorFlags(bits: layout._positiveSizeOrExtraFlags)
  }

  /// The Objective-C resilient class stub, if this descriptor records one.
  public var objcResilientClassStub: UnsafeRawPointer? {
    guard let offset = trailingLayout.objcResilientClassStub else { return nil }
    let field = trailing + offset
    let reference = field.load(as: RelativeDirectPointer<Void>.self)
    guard reference.isNull == false else { return nil }
    return reference.address(from: field)
  }

  /// Canonical metadata specializations emitted for this generic class.
  public var canonicalMetadataPrespecializations: [Metadata] {
    guard let offset = trailingLayout.canonicalMetadataList else { return [] }
    return Array(unsafeUninitializedCapacity: trailingLayout.canonicalMetadataCount) {
      for index in 0 ..< trailingLayout.canonicalMetadataCount {
        let field = (trailing + offset).advanced(
          by: index * MemoryLayout<RelativeDirectPointer<Void>>.stride
        )
        $0[index] = getMetadata(at: field.relativeDirectAddress(as: Void.self))
      }
      $1 = trailingLayout.canonicalMetadataCount
    }
  }

  /// Accessors corresponding to `canonicalMetadataPrespecializations`.
  public var canonicalMetadataPrespecializationAccessors: [MetadataAccessFunction] {
    guard let offset = trailingLayout.canonicalMetadataAccessorList else { return [] }
    return Array(unsafeUninitializedCapacity: trailingLayout.canonicalMetadataCount) {
      for index in 0 ..< trailingLayout.canonicalMetadataCount {
        let field = (trailing + offset).advanced(
          by: index * MemoryLayout<RelativeDirectPointer<Void>>.stride
        )
        $0[index] = MetadataAccessFunction(
          ptr: field.relativeDirectAddress(as: Void.self)
        )
      }
      $1 = trailingLayout.canonicalMetadataCount
    }
  }

  /// Capabilities this class's primary definition explicitly inverts.
  public var invertedProtocols: InvertibleProtocolSet? {
    guard let offset = trailingLayout.invertedProtocols else { return nil }
    return InvertibleProtocolSet(bits: (trailing + offset).load(as: UInt16.self))
  }

  /// The directly stored singleton metadata, when the compiler emitted one.
  public var singletonMetadata: Metadata? {
    guard let offset = trailingLayout.singletonMetadata else { return nil }
    let field = trailing + offset
    return getMetadata(at: field.relativeDirectAddress(as: Void.self))
  }

  /// Header for default method overrides inherited by subclasses.
  public var defaultOverrideTableHeader: DefaultOverrideTableHeader? {
    guard let offset = trailingLayout.defaultOverrideTableHeader else { return nil }
    return DefaultOverrideTableHeader(ptr: trailing + offset)
  }

  /// Default method override records emitted for this class.
  public var defaultOverrideDescriptors: [MethodDefaultOverrideDescriptor] {
    guard let offset = trailingLayout.defaultOverrideDescriptors else { return [] }
    return Array(unsafeUninitializedCapacity: trailingLayout.numDefaultOverrideDescriptors) {
      for index in 0 ..< trailingLayout.numDefaultOverrideDescriptors {
        $0[index] = MethodDefaultOverrideDescriptor(
          ptr: (trailing + offset).advanced(
            by: index * MemoryLayout<_MethodDefaultOverrideDescriptor>.stride
          )
        )
      }
      $1 = trailingLayout.numDefaultOverrideDescriptors
    }
  }

  private var trailingLayout: TrailingLayout {
    var cursor = flags.isGeneric ? typeGenericContext.size : 0
    var resilientSuperclass: Int?
    var foreignMetadataInitialization: Int?
    var singletonMetadataInitialization: Int?
    var vtableHeader: Int?
    var methodDescriptors: Int?
    var numMethodDescriptors = 0
    var overrideTableHeader: Int?
    var methodOverrideDescriptors: Int?
    var numMethodOverrideDescriptors = 0
    var objcResilientClassStub: Int?
    var canonicalMetadataList: Int?
    var canonicalMetadataAccessorList: Int?
    var canonicalMetadataCount = 0
    var invertedProtocols: Int?
    var singletonMetadata: Int?
    var defaultOverrideTableHeader: Int?
    var defaultOverrideDescriptors: Int?
    var numDefaultOverrideDescriptors = 0

    if typeFlags.classHasResilientSuperclass {
      resilientSuperclass = cursor
      cursor += MemoryLayout<RelativeDirectPointer<Void>>.stride
    }

    switch typeFlags.metadataInitKind {
    case .foreign:
      foreignMetadataInitialization = cursor
      cursor += MemoryLayout<_ForeignMetadataInitialization>.stride
    case .singleton:
      singletonMetadataInitialization = cursor
      cursor += MemoryLayout<_SingletonMetadataInitialization>.stride
    case .none:
      break
    }

    if typeFlags.classHasVTable {
      vtableHeader = cursor
      numMethodDescriptors = Int(
        (trailing + cursor).load(as: _VTableDescriptorHeader.self)._size
      )
      cursor += MemoryLayout<_VTableDescriptorHeader>.stride
      methodDescriptors = cursor
      cursor += numMethodDescriptors * MemoryLayout<_MethodDescriptor>.stride
    }

    if typeFlags.classHasOverrideTable {
      overrideTableHeader = cursor
      numMethodOverrideDescriptors = Int(
        (trailing + cursor).load(as: _OverrideTableHeader.self)._numEntries
      )
      cursor += MemoryLayout<_OverrideTableHeader>.stride
      methodOverrideDescriptors = cursor
      cursor += numMethodOverrideDescriptors * MemoryLayout<_MethodOverrideDescriptor>.stride
    }

    if extraClassFlags?.hasObjCResilientClassStub == true {
      objcResilientClassStub = cursor
      cursor += MemoryLayout<RelativeDirectPointer<Void>>.stride
    }

    if flags.isGeneric && typeFlags.hasCanonicalMetadataPrespecializationsOrSingletonMetadataPointer {
      canonicalMetadataCount = Int((trailing + cursor).load(as: UInt32.self))
      cursor += MemoryLayout<UInt32>.stride
      canonicalMetadataList = cursor
      cursor += canonicalMetadataCount * MemoryLayout<RelativeDirectPointer<Void>>.stride
      canonicalMetadataAccessorList = cursor
      cursor += canonicalMetadataCount * MemoryLayout<RelativeDirectPointer<Void>>.stride
      cursor += MemoryLayout<RelativeDirectPointer<Void>>.stride
    }

    if flags.hasInvertibleProtocols {
      invertedProtocols = cursor
      cursor += MemoryLayout<UInt16>.stride
    }

    if !flags.isGeneric && typeFlags.hasCanonicalMetadataPrespecializationsOrSingletonMetadataPointer {
      cursor = Self.aligned(cursor, to: MemoryLayout<RelativeDirectPointer<Void>>.alignment)
      singletonMetadata = cursor
      cursor += MemoryLayout<RelativeDirectPointer<Void>>.stride
    }

    if typeFlags.classHasDefaultOverrideTable {
      cursor = Self.aligned(cursor, to: MemoryLayout<_DefaultOverrideTableHeader>.alignment)
      defaultOverrideTableHeader = cursor
      numDefaultOverrideDescriptors = Int(
        (trailing + cursor).load(as: _DefaultOverrideTableHeader.self)._numEntries
      )
      cursor += MemoryLayout<_DefaultOverrideTableHeader>.stride
      defaultOverrideDescriptors = cursor
    }

    return TrailingLayout(
      resilientSuperclass: resilientSuperclass,
      foreignMetadataInitialization: foreignMetadataInitialization,
      singletonMetadataInitialization: singletonMetadataInitialization,
      vtableHeader: vtableHeader,
      methodDescriptors: methodDescriptors,
      numMethodDescriptors: numMethodDescriptors,
      overrideTableHeader: overrideTableHeader,
      methodOverrideDescriptors: methodOverrideDescriptors,
      numMethodOverrideDescriptors: numMethodOverrideDescriptors,
      objcResilientClassStub: objcResilientClassStub,
      canonicalMetadataList: canonicalMetadataList,
      canonicalMetadataAccessorList: canonicalMetadataAccessorList,
      canonicalMetadataCount: canonicalMetadataCount,
      invertedProtocols: invertedProtocols,
      singletonMetadata: singletonMetadata,
      defaultOverrideTableHeader: defaultOverrideTableHeader,
      defaultOverrideDescriptors: defaultOverrideDescriptors,
      numDefaultOverrideDescriptors: numDefaultOverrideDescriptors
    )
  }

  private static func aligned(_ value: Int, to alignment: Int) -> Int {
    (value + alignment - 1) & -alignment
  }

  private struct TrailingLayout {
    let resilientSuperclass: Int?
    let foreignMetadataInitialization: Int?
    let singletonMetadataInitialization: Int?
    let vtableHeader: Int?
    let methodDescriptors: Int?
    let numMethodDescriptors: Int
    let overrideTableHeader: Int?
    let methodOverrideDescriptors: Int?
    let numMethodOverrideDescriptors: Int
    let objcResilientClassStub: Int?
    let canonicalMetadataList: Int?
    let canonicalMetadataAccessorList: Int?
    let canonicalMetadataCount: Int
    let invertedProtocols: Int?
    let singletonMetadata: Int?
    let defaultOverrideTableHeader: Int?
    let defaultOverrideDescriptors: Int?
    let numDefaultOverrideDescriptors: Int
  }
  
  // Internal methods related to Metadata bounds and argument offsets.
  
  var genericArgumentOffset: Int {
    if typeFlags.classHasResilientSuperclass {
      return resilientImmediateMembersOffset
    } else {
      return nonResilientImmediateMembersOffset
    }
  }
  
  var nonResilientImmediateMembersOffset: Int {
    assert(!typeFlags.classHasResilientSuperclass)
    
    if typeFlags.classAreImmediateMembersNegative {
      return -negativeSize
    } else {
      return positiveSize - numMembers
    }
  }
  
  var metadataBoundsForSwiftClass: (Int, Int, Int) {
    let immediateMemberOffset = MemoryLayout<_ClassMetadata>.size
    let positiveSize = MemoryLayout<_ClassMetadata>.size / MemoryLayout<Int>.size
    // This is the class metadata header size, which is the destructor pointer
    // + the value witness table pointer = 16 bytes.
    // 16 bytes / sizeof(void *) = 2
    let negativeSize = 2
    
    return (immediateMemberOffset, positiveSize, negativeSize)
  }
  
  var resilientImmediateMembersOffset: Int {
    assert(typeFlags.classHasResilientSuperclass)
    
    let immediateMembersOffset = resilientBounds.immediateMembersOffset
    
    // If this value is already cached, use it.
    if immediateMembersOffset != 0 {
      return immediateMembersOffset / MemoryLayout<Int>.size
    }
    
    // Otherwise, we're going to need to compute it.
    var immediateMemberOffset = 0
    var positiveSize = 0
    var negativeSize = 0
    
    if let superclass = resilientSuperclass {
      
      func getMetadataBoundsForObjCClass(_ cls: AnyClass) -> (Int, Int, Int) {
        let metadata = reflectClass(cls)!
        
        let rootBounds = metadataBoundsForSwiftClass
        // 0 = Immediate member offset, 1 = positive size, 2 = negative size
        var bounds = (0, 0, 0)
        
        if !metadata.isSwiftClass {
          return rootBounds
        }
        
        bounds.0 = metadata.classSize - metadata.classAddressPoint
        bounds.1 = (metadata.classSize - metadata.classAddressPoint) / MemoryLayout<Int>.size
        bounds.2 = metadata.classAddressPoint / MemoryLayout<Int>.size
        
        if bounds.2 < rootBounds.2 {
          bounds.2 = rootBounds.2
        }
        
        if bounds.1 < rootBounds.1 {
          bounds.1 = rootBounds.1
        }
        
        return bounds
      }
      
      switch typeFlags.resilientSuperclassRefKind {
      case .indirectTypeDescriptor:
        let descriptor = ClassDescriptor(
          ptr: superclass.load(as: SignedPointer<ClassDescriptor>.self).signed
        )
        immediateMemberOffset = descriptor.genericArgumentOffset
        
      case .directTypeDescriptor:
        let descriptor = ClassDescriptor(ptr: superclass)
        immediateMemberOffset = descriptor.genericArgumentOffset
        
      case .directObjCClass:
        #if canImport(ObjectiveC)
        let name = UnsafePointer<CChar>(superclass._rawValue)
        guard var cls = objc_lookUpClass(name) else {
          let name = String(cString: name)
          fatalError("Failed to lookup Objective-C class named: \(name)")
        }
        
        cls = swift_getInitializedObjCClass(cls)
        (immediateMemberOffset, positiveSize, negativeSize) =
          getMetadataBoundsForObjCClass(cls)
        #else
        break
        #endif
        
      case .indirectObjCClass:
        #if canImport(ObjectiveC)
        let cls = UnsafePointer<AnyClass>(superclass._rawValue)
        (immediateMemberOffset, positiveSize, negativeSize) =
          getMetadataBoundsForObjCClass(cls.pointee)
        #else
        break
        #endif
      }
    } else {
      (immediateMemberOffset, positiveSize, negativeSize) =
        metadataBoundsForSwiftClass
    }
    
    if typeFlags.classAreImmediateMembersNegative {
      negativeSize += numMembers
      immediateMemberOffset = -negativeSize * MemoryLayout<Int>.size
    } else {
      immediateMemberOffset = positiveSize * MemoryLayout<Int>.size
      positiveSize += numMembers
    }
    
    let start = address(for: \._negativeSizeOrResilientBounds)
    let bounds = UnsafeMutablePointer(mutating: start.relativeDirectAddress(
      as: _StoredClassMetadataBounds.self
    ).assumingMemoryBound(to: _StoredClassMetadataBounds.self))
    
    bounds.pointee._bounds._positiveSize = UInt32(positiveSize)
    bounds.pointee._bounds._negativeSize = UInt32(negativeSize)
    
    bounds.withMemoryRebound(to: UnsafeAtomic<Int>.Storage.self, capacity: 1) {
      UnsafeAtomic<Int>.Storage.atomicStore(
        immediateMemberOffset,
        at: $0,
        ordering: .releasing
      )
    }
    
    return immediateMemberOffset / MemoryLayout<Int>.size
  }
}

extension ClassDescriptor: Equatable {}

/// Structure that helps in determining where the vtable for a class is within
/// the type metadata and how many vtable entries there are.
public struct VTableDescriptorHeader: LayoutWrapper {
  typealias Layout = _VTableDescriptorHeader
  
  /// Backing VTableDescriptorHeader pointer.
  let ptr: UnsafeRawPointer
  
  /// The offset to the vtable from the class metadata.
  public var offset: Int {
    Int(layout._offset)
  }
  
  /// The number of vtable methods.
  public var size: Int {
    Int(layout._size)
  }
}

/// Structure that describes a class or protocol method.
public struct MethodDescriptor: LayoutWrapper {
  typealias Layout = _MethodDescriptor
  
  /// Backing MethodDescriptor pointer.
  let ptr: UnsafeRawPointer
  
  /// Flags that describe this method descriptor.
  public var flags: Flags {
    layout._flags
  }
}

/// Structure that tells the number of method override entries in a class
/// descriptor.
public struct OverrideTableHeader: LayoutWrapper {
  typealias Layout = _OverrideTableHeader
  
  /// Backing OverrideTableHeader pointer.
  let ptr: UnsafeRawPointer
  
  /// The number of override method entries.
  public var numEntries: Int {
    Int(layout._numEntries)
  }
}

/// A method override descriptor describes the method being overriden from what
/// class.
public struct MethodOverrideDescriptor: LayoutWrapper {
  typealias Layout = _MethodOverrideDescriptor
  
  /// Backing MethodOverrideDescriptor pointer.
  let ptr: UnsafeRawPointer
  
  /// The class containing the base method.
  public var `class`: ContextDescriptor {
    getContextDescriptor(at: address(for: \._class))
  }
  
  /// The base method descriptor.
  public var method: MethodDescriptor {
    MethodDescriptor(ptr: address(for: \._method))
  }
}

/// Header for a table of default method override records.
public struct DefaultOverrideTableHeader: LayoutWrapper {
  typealias Layout = _DefaultOverrideTableHeader

  let ptr: UnsafeRawPointer

  /// The number of default override records in the table.
  public var numEntries: Int {
    Int(layout._numEntries)
  }
}

/// A default method override inherited by subclasses that do not provide an
/// implementation of their own.
public struct MethodDefaultOverrideDescriptor: LayoutWrapper {
  typealias Layout = _MethodDefaultOverrideDescriptor

  let ptr: UnsafeRawPointer

  /// The method selected at replacement call sites.
  public var replacement: MethodDescriptor? {
    let field = address(for: \._replacement)
    let reference = layout._replacement
    guard reference.isNull == false else { return nil }
    return MethodDescriptor(ptr: reference.address(from: field))
  }

  /// The method originally selected at those call sites.
  public var original: MethodDescriptor? {
    let field = address(for: \._original)
    let reference = layout._original
    guard reference.isNull == false else { return nil }
    return MethodDescriptor(ptr: reference.address(from: field))
  }

  /// The opaque replacement implementation pointer. It must not be invoked
  /// directly.
  public var implementation: UnsafeRawPointer? {
    let field = address(for: \._implementation)
    let reference = layout._implementation
    guard reference.isNull == false else { return nil }
    return reference.address(from: field)
  }
}

/// Bounds for metadata objects.
public struct MetadataBounds {
  var _negativeSize: UInt32
  var _positiveSize: UInt32
  
  /// The negative size of the metadata in words.
  public var negativeSize: Int {
    Int(_negativeSize)
  }
  
  /// The positive size of the metadata in words.
  public var positiveSize: Int {
    Int(_positiveSize)
  }
}

struct _ClassDescriptor {
  let _base: _TypeDescriptor
  let _superclass: RelativeDirectPointer<CChar>
  
  // This is either a uint32 for negative size, or a relative direct pointer
  // to class metadata bounds if the superclass is resilient.
  let _negativeSizeOrResilientBounds: UInt32
  
  // This is either a uint32 for positive size, or extra class flags
  // if the superclass is resilient.
  let _positiveSizeOrExtraFlags: UInt32
  
  let _numImmediateMembers: UInt32
  let _numFields: UInt32
  let _fieldOffsetVectorOffset: UInt32
}

struct _StoredClassMetadataBounds {
  var _immediateMembersOffset: UnsafeAtomic<Int>.Storage
  var _bounds: MetadataBounds
}

struct StoredClassMetadataBounds: LayoutWrapper {
  typealias Layout = _StoredClassMetadataBounds
  
  let ptr: UnsafeRawPointer
  
  var immediateMembersOffset: Int {
    UnsafeAtomic<Int>.Storage.atomicLoad(
      at: ptr.mutable.bindMemory(to: UnsafeAtomic<Int>.Storage.self, capacity: 1),
      ordering: .relaxed
    )
  }
}

struct _VTableDescriptorHeader {
  let _offset: UInt32
  let _size: UInt32
}

struct _MethodDescriptor {
  let _flags: MethodDescriptor.Flags
  let _impl: RelativeDirectPointer<Void>
}

struct _OverrideTableHeader {
  let _numEntries: UInt32
}

struct _MethodOverrideDescriptor {
  let _class: RelativeIndirectablePointer<_ContextDescriptor>
  let _method: RelativeIndirectablePointer<_MethodDescriptor>
  let _impl: RelativeDirectPointer<Void>
}

struct _DefaultOverrideTableHeader {
  let _numEntries: UInt32
}

struct _MethodDefaultOverrideDescriptor {
  let _replacement: RelativeIndirectablePointer<_MethodDescriptor>
  let _original: RelativeIndirectablePointer<_MethodDescriptor>
  let _implementation: RelativeDirectPointer<Void>
}
