//
//  StructDescriptor.swift
//  Echo
//
//  Created by Alejandro Alonso
//  Copyright © 2019 - 2020 Alejandro Alonso. All rights reserved.
//

/// A struct descriptor that describes some structure context.
///
/// ABI Stability: Stable since the following
///
///     | macOS | iOS/tvOS | watchOS | Linux | Windows |
///     |-------|----------|---------|-------|---------|
///     | 10.14 | 12.2     | 5.2     | NA    | NA      |
///
public struct StructDescriptor: TypeContextDescriptor, LayoutWrapper {
  typealias Layout = _StructDescriptor
  
  /// Backing context descriptor pointer.
  public let ptr: UnsafeRawPointer
  
  /// The number of stored properties this struct defines.
  public var numFields: Int {
    Int(layout._numFields)
  }
  
  /// The number of words from the metadata pointer to the vector of field
  /// offsets for this struct.
  /// E.g. If this is 2:
  ///   let fieldOffsetVector = metadataPtr + MemoryLayout<Int>.size * 2
  ///   // fieldOffsetVector is a buffer pointer to Int32's that tell the
  ///   // stored offset for a specific field at index i.
  public var fieldOffsetVectorOffset: Int {
    Int(layout._fieldOffsetVectorOffset)
  }
  
  /// The foreign metadata initialization info for this struct metadata, if it
  /// has any.
  public var foreignMetadataInitialization: ForeignMetadataInitialization? {
    guard let offset = trailingLayout.foreignMetadataInitialization else { return nil }
    return ForeignMetadataInitialization(ptr: trailing + offset)
  }
  
  /// The singleton metadata initialization info for this struct metadata, if it
  /// has any.
  public var singletonMetadataInitialization: SingletonMetadataInitialization? {
    guard let offset = trailingLayout.singletonMetadataInitialization else { return nil }
    return SingletonMetadataInitialization(ptr: trailing + offset)
  }

  /// Canonical metadata specializations emitted for this generic type.
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

  /// The runtime-owned once-token used to cache this generic type's canonical
  /// metadata prespecializations. This storage is exposed for inspection only
  /// and must not be mutated.
  public var canonicalMetadataPrespecializationCachingOnceToken: UnsafeRawPointer? {
    guard let offset = trailingLayout.canonicalMetadataCachingToken else {
      return nil
    }
    let field = trailing + offset
    let reference = field.load(as: RelativeDirectPointer<Void>.self)
    guard reference.isNull == false else { return nil }
    return reference.address(from: field)
  }

  /// Capabilities this type's primary definition explicitly inverts.
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

  private var trailingLayout: ValueTypeDescriptorTrailingLayout {
    ValueTypeDescriptorTrailingLayout(
      trailing: trailing,
      isGeneric: flags.isGeneric,
      genericContextSize: flags.isGeneric ? typeGenericContext.size : 0,
      typeFlags: typeFlags,
      hasInvertibleProtocols: flags.hasInvertibleProtocols
    )
  }
}

extension StructDescriptor: Equatable {}

struct _StructDescriptor {
  let _base: _TypeDescriptor
  let _numFields: UInt32
  let _fieldOffsetVectorOffset: UInt32
}
