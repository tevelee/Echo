//
//  EnumMetadata.swift
//  Echo
//
//  Created by Alejandro Alonso
//  Copyright © 2019 - 2021 Alejandro Alonso. All rights reserved.
//

/// The metadata structure that represents an `enum` type in Swift.
///
/// ABI Stability: Stable since the following
///
///     | macOS | iOS/tvOS | watchOS | Linux | Windows |
///     |-------|----------|---------|-------|---------|
///     | 10.14 | 12.2     | 5.2     | NA    | NA      |
///
public struct EnumMetadata: TypeMetadata, LayoutWrapper {
  typealias Layout = _EnumMetadata
  
  /// Backing enum metadata pointer.
  public let ptr: UnsafeRawPointer
  
  /// The enum context descriptor that describes this enum.
  public var descriptor: EnumDescriptor {
    EnumDescriptor(ptr: layout._descriptor.signed)
  }

  /// Flags recorded after this generic enum metadata's arguments and optional
  /// payload-size word when the compiler emitted a static specialization.
  public var trailingFlags: MetadataTrailingFlags? {
    guard descriptor.flags.isGeneric,
          descriptor.typeGenericContext.genericMetadataPattern.flags.hasTrailingFlags
    else {
      return nil
    }

    let genericArgumentOffset = MemoryLayout<_EnumMetadata>.size / MemoryLayout<UnsafeRawPointer>.size
    let argumentCount = descriptor.typeGenericContext.numKeyArguments
    let payloadSizeWords = descriptor.hasPayloadSizeOffset ? 1 : 0
    let address = ptr.offset(of: genericArgumentOffset + argumentCount + payloadSizeWords)
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

extension EnumMetadata: Equatable {}

struct _EnumMetadata {
  let _kind: Int
  let _descriptor: SignedPointer<EnumDescriptor>
}
