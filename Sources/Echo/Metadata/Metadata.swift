//
//  Metadata.swift
//  Echo
//
//  Created by Alejandro Alonso
//  Copyright © 2019 - 2021 Alejandro Alonso. All rights reserved.
//

/// Metadata refers to the Swift metadata records in a given binary. All
/// metadata records include a value witness table, which describe how to
/// properly copy, destroy, etc. the memory of a type, along with a given
/// "kind".
public protocol Metadata {
  /// Backing metadata pointer.
  var ptr: UnsafeRawPointer { get }
}

extension Metadata {
  /// The unprocessed metadata kind word stored by the runtime.
  ///
  /// Values above the runtime's enumerated-kind range are Objective-C ISA
  /// pointers. Values within that range can be introduced by newer Swift
  /// runtimes, so prefer `knownKind` before relying on `kind` for dispatch.
  public var rawKind: Int {
    ptr.load(as: Int.self)
  }

  /// The known metadata kind, or `nil` for a future enumerated kind.
  public var knownKind: MetadataKind? {
    MetadataKind(rawValue: rawKind)
  }

  /// Whether this record is metadata for a type and therefore has value
  /// witnesses. ISA-pointer class metadata is always type metadata.
  public var isTypeMetadata: Bool {
    rawKind > 0x7FF || rawKind & MetadataKind.Flags.isNonType.rawValue == 0
  }

  /// The type that this metadata represents.
  public var type: Any.Type {
    precondition(isTypeMetadata, "Runtime object metadata does not represent a Swift type")
    return unsafeBitCast(ptr, to: Any.Type.self)
  }
  
  /// The value witness table for this type metadata.
  public var vwt: ValueWitnessTable {
    precondition(isTypeMetadata, "Runtime object metadata has no value witness table")
    let address = ptr.offset(of: -1)
    return ValueWitnessTable(ptr: address)
  }
  
  /// The enum value witness table for this enum metadata.
  public var enumVwt: EnumValueWitnessTable {
    precondition(isTypeMetadata, "Runtime object metadata has no enum value witness table")
    precondition(kind == .enum || kind == .optional)
    let address = ptr.offset(of: -1)
    return EnumValueWitnessTable(ptr: address)
  }
  
  /// The kind of metadata this is.
  public var kind: MetadataKind {
    // ISA pointer. Obj-C compatibile
    guard let kind = knownKind else {
      return .class
    }
    
    return kind
  }
}

extension Metadata {
  // Allocation methods
  
  /// Given a pointer to some existential container, allocate a box on the heap
  /// for the container to put the type's value in.
  /// - Parameter container: Pointer to some existential container.
  /// - Returns: A pointer to the newly allocated buffer. If the value is
  ///            stored inline, then this is a pointer to the container's
  ///            data field.
  public func allocateBoxForExistential(
    in container: UnsafeMutablePointer<AnyExistentialContainer>
  ) -> UnsafeRawPointer {
    guard !vwt.flags.isValueInline else {
      return container.raw
    }
    
    let box = swift_allocBox(for: self)
    container.pointee.data.0 = Int(bitPattern: box.heapObj)
    return box.buffer
  }
}

func getMetadataKind(at ptr: UnsafeRawPointer) -> MetadataKind? {
  // If we can't form a metadata kind here, it is most likely an obj-c
  // compatible class whose kind is the ISA pointer address.
  let rawKind = ptr.load(as: Int.self)
  guard rawKind <= 0x7FF else {
    return .class
  }

  return MetadataKind(rawValue: rawKind)
}

// Determine what metadata to return given a blank pointer to some metadata.
func getMetadata(at ptr: UnsafeRawPointer) -> Metadata {
  let int = ptr.load(as: Int.self)
  let kind = MetadataKind(rawValue: int)
  
  switch kind {
  case .class:
    return ClassMetadata(ptr: ptr)
  case .struct:
    return StructMetadata(ptr: ptr)
  case .enum, .optional:
    return EnumMetadata(ptr: ptr)
  case .foreignClass:
    return ForeignClassMetadata(ptr: ptr)
  case .foreignReferenceType:
    return ForeignReferenceTypeMetadata(ptr: ptr)
  case .opaque:
    return OpaqueMetadata(ptr: ptr)
  case .tuple:
    return TupleMetadata(ptr: ptr)
  case .function:
    return FunctionMetadata(ptr: ptr)
  case .existential:
    return ExistentialMetadata(ptr: ptr)
  case .metatype:
    return MetatypeMetadata(ptr: ptr)
  case .objcClassWrapper:
    return ObjCClassWrapperMetadata(ptr: ptr)
  case .existentialMetatype:
    return ExistentialMetatypeMetadata(ptr: ptr)
  case .extendedExistential:
    return ExtendedExistentialMetadata(ptr: ptr)
  case .fixedArray:
    return FixedArrayMetadata(ptr: ptr)
  case .heapLocalVariable:
    return HeapLocalVariableMetadata(ptr: ptr)
  case .heapGenericLocalVariable:
    return HeapGenericLocalVariableMetadata(ptr: ptr)
  case .errorObject, .task, .job:
    return UnknownMetadata(ptr: ptr)
  default:
    // ISA pointer. Obj-C compatibile
    if int > 2047 {
      return ClassMetadata(ptr: ptr)
    }

    return UnknownMetadata(ptr: ptr)
  }
}

/// A metadata record whose enumerated kind is newer than Echo understands, or
/// a runtime-private non-type record. Its raw word remains available through
/// `rawKind`; type-only operations deliberately precondition-fail.
public struct UnknownMetadata: Metadata {
  /// Backing metadata pointer.
  public let ptr: UnsafeRawPointer
}

extension UnknownMetadata: Equatable {}
