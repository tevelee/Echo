//
//  ValueTypeDescriptorTrailing.swift
//  Echo
//
//  Created by Alejandro Alonso
//  Copyright © 2026 Alejandro Alonso. All rights reserved.
//

/// Offsets for the trailing records shared by struct and enum descriptors.
///
/// The order matches `TargetStructDescriptor` and `TargetEnumDescriptor` in
/// Swift's stable ABI: generic context, metadata initialization, canonical
/// prespecializations, inverted protocols, then singleton metadata.
struct ValueTypeDescriptorTrailingLayout {
  let foreignMetadataInitialization: Int?
  let singletonMetadataInitialization: Int?
  let canonicalMetadataList: Int?
  let canonicalMetadataCount: Int
  let canonicalMetadataCachingToken: Int?
  let invertedProtocols: Int?
  let singletonMetadata: Int?

  init(
    trailing: UnsafeRawPointer,
    isGeneric: Bool,
    genericContextSize: Int,
    typeFlags: TypeContextDescriptorFlags,
    hasInvertibleProtocols: Bool
  ) {
    var cursor = isGeneric ? genericContextSize : 0
    var foreignMetadataInitialization: Int?
    var singletonMetadataInitialization: Int?
    var canonicalMetadataList: Int?
    var canonicalMetadataCount = 0
    var canonicalMetadataCachingToken: Int?
    var invertedProtocols: Int?
    var singletonMetadata: Int?

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

    if isGeneric && typeFlags.hasCanonicalMetadataPrespecializationsOrSingletonMetadataPointer {
      canonicalMetadataCount = Int(
        (trailing + cursor).load(as: UInt32.self)
      )
      cursor += MemoryLayout<UInt32>.stride
      canonicalMetadataList = cursor
      cursor += canonicalMetadataCount * MemoryLayout<RelativeDirectPointer<Void>>.stride
      canonicalMetadataCachingToken = cursor
      cursor += MemoryLayout<RelativeDirectPointer<Void>>.stride
    }

    if hasInvertibleProtocols {
      invertedProtocols = cursor
      cursor += MemoryLayout<UInt16>.stride
    }

    if !isGeneric && typeFlags.hasCanonicalMetadataPrespecializationsOrSingletonMetadataPointer {
      singletonMetadata = cursor
    }

    self.foreignMetadataInitialization = foreignMetadataInitialization
    self.singletonMetadataInitialization = singletonMetadataInitialization
    self.canonicalMetadataList = canonicalMetadataList
    self.canonicalMetadataCount = canonicalMetadataCount
    self.canonicalMetadataCachingToken = canonicalMetadataCachingToken
    self.invertedProtocols = invertedProtocols
    self.singletonMetadata = singletonMetadata
  }
}
