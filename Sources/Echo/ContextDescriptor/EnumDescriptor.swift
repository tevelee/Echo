//
//  EnumDescriptor.swift
//  Echo
//
//  Created by Alejandro Alonso
//  Copyright © 2019 - 2020 Alejandro Alonso. All rights reserved.
//

/// An enum descriptor that describes some enum context.
///
/// ABI Stability: Stable since the following
///
///     | macOS | iOS/tvOS | watchOS | Linux | Windows |
///     |-------|----------|---------|-------|---------|
///     | 10.14 | 12.2     | 5.2     | NA    | NA      |
///
public struct EnumDescriptor: TypeContextDescriptor, LayoutWrapper {
  typealias Layout = _EnumDescriptor
  
  /// Backing context descriptor pointer.
  public let ptr: UnsafeRawPointer
  
  /// The number of enum cases which have payloads (associated types).
  /// Ex. case number(Int)
  public var numPayloadCases: Int {
    Int(layout._numPayloadCasesAndPayloadSizeOffset) & 0xFFFFFF
  }
  
  /// The payload size offset is the number of words from the metadata pointer
  /// to the payload size, if any.
  public var payloadSizeOffset: Int {
    Int((layout._numPayloadCasesAndPayloadSizeOffset & 0xFF000000) >> 24)
  }
  
  /// Whether or not this enum has a payload size offset.
  public var hasPayloadSizeOffset: Bool {
    payloadSizeOffset != 0
  }
  
  /// The number of enum cases that have no payload.
  /// Ex. case blue
  public var numEmptyCases: Int {
    Int(layout._numEmptyCases)
  }
  
  /// The total number of cases this enum has.
  public var numCases: Int {
    numEmptyCases + numPayloadCases
  }
  
  /// The foreign metadata initialization info for this enum metadata, if it
  /// has any.
  public var foreignMetadataInitialization: ForeignMetadataInitialization? {
    guard let offset = trailingLayout.foreignMetadataInitialization else { return nil }
    return ForeignMetadataInitialization(ptr: trailing + offset)
  }
  
  /// The singleton metadata initialization info for this enum metadata, if it
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

extension EnumDescriptor: Equatable {}

struct _EnumDescriptor {
  let _base: _TypeDescriptor
  let _numPayloadCasesAndPayloadSizeOffset: UInt32
  let _numEmptyCases: UInt32
}
