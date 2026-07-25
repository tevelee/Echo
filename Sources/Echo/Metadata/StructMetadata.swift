//
//  StructMetadata.swift
//  Echo
//
//  Created by Alejandro Alonso
//  Copyright © 2019 - 2021 Alejandro Alonso. All rights reserved.
//

/// The metadata structure that represents a `struct` type in Swift.
///
/// ABI Stability: Stable since the following
///
///     | macOS | iOS/tvOS | watchOS | Linux | Windows |
///     |-------|----------|---------|-------|---------|
///     | 10.14 | 12.2     | 5.2     | NA    | NA      |
///
public struct StructMetadata: TypeMetadata, LayoutWrapper {
  typealias Layout = _StructMetadata
  
  /// Backing struct metadata pointer.
  public let ptr: UnsafeRawPointer
  
  /// The struct context descriptor that describes this struct.
  public var descriptor: StructDescriptor {
    StructDescriptor(ptr: layout._descriptor.signed)
  }
  
  /// An array of field offsets for this struct's stored representation.
  public var fieldOffsets: [Int] {
    let start = ptr.offset(of: descriptor.fieldOffsetVectorOffset)
    
    return Array(unsafeUninitializedCapacity: descriptor.numFields) {
      for i in 0 ..< descriptor.numFields {
        let offset = start.load(
          fromByteOffset: i * MemoryLayout<UInt32>.size,
          as: UInt32.self
        )
        
        $0[i] = Int(offset)
      }
      
      $1 = descriptor.numFields
    }
  }

  /// Flags recorded after this generic struct metadata's field-offset vector
  /// when the compiler emitted a static specialization.
  public var trailingFlags: MetadataTrailingFlags? {
    guard descriptor.flags.isGeneric,
          descriptor.typeGenericContext.genericMetadataPattern.flags.hasTrailingFlags
    else {
      return nil
    }

    let fieldOffsetWords = descriptor.fieldOffsetVectorOffset
    let fieldOffsetVectorWords = (
      descriptor.numFields * MemoryLayout<UInt32>.stride + MemoryLayout<UnsafeRawPointer>.size - 1
    ) / MemoryLayout<UnsafeRawPointer>.size
    let address = ptr.offset(of: fieldOffsetWords + fieldOffsetVectorWords)
    return MetadataTrailingFlags(bits: address.loadUnaligned(as: UInt64.self))
  }

  /// Whether this metadata is a generic specialization created during
  /// compilation.
  public var isStaticallySpecializedGenericMetadata: Bool {
    trailingFlags?.isStaticSpecialization == true
  }

  /// Whether this compiled generic specialization was made canonical by its
  /// metadata accessor.
  public var isCanonicalStaticallySpecializedGenericMetadata: Bool {
    trailingFlags?.isCanonicalStaticSpecialization == true
  }
}

extension StructMetadata: Equatable {}

struct _StructMetadata {
  let _kind: Int
  let _descriptor: SignedPointer<StructDescriptor>
}
