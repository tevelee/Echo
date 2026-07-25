//
//  AssociatedType.swift
//  Echo
//
//  Created by Alejandro Alonso
//  Copyright © 2026 Alejandro Alonso. All rights reserved.
//

import CEcho

extension ProtocolDescriptor {
  /// The names of this protocol's associated types in declaration order.
  public var associatedTypeNameList: [String] {
    associatedTypeNames.split(separator: " ").map(String.init)
  }

  /// Resolves the metadata bound to an associated type for a conformance.
  ///
  /// - Parameters:
  ///   - name: The associated type name, such as `"Element"`.
  ///   - conformingType: Metadata for the conforming type.
  ///   - witnessTable: The conformance's witness table.
  /// - Returns: The associated type's metadata, or `nil` if this descriptor
  ///   does not define `name` or the required witness is unavailable.
  public func associatedTypeWitness(
    named name: String,
    conformingType: Metadata,
    witnessTable: WitnessTable
  ) -> Metadata? {
    guard let nameIndex = associatedTypeNameList.firstIndex(of: name) else {
      return nil
    }

    let protocolRequirements = requirements
    guard let firstRequirement = protocolRequirements.first else { return nil }

    // The ABI defines the witness-table's first requirement at offset one
    // from the requirement base. Recover that base from the first record.
    let requirementBase = firstRequirement.ptr
      - MemoryLayout<_ProtocolRequirement>.size

    let associatedTypeRequirements = protocolRequirements.filter {
      $0.flags.kind == .associatedTypeAccessFunction
    }
    guard associatedTypeRequirements.indices.contains(nameIndex) else {
      return nil
    }

    let response = echo_swift_getAssociatedTypeWitness(
      MetadataRequest.complete.bits,
      witnessTable.ptr,
      conformingType.ptr,
      requirementBase,
      associatedTypeRequirements[nameIndex].ptr
    )
    return unsafeBitCast(response, to: MetadataResponse.self).metadata
  }
}

extension TypeMetadata {
  /// Resolves an associated type from this type's conformance to a protocol.
  ///
  /// - Parameters:
  ///   - name: The associated type name, such as `"Element"`.
  ///   - protocolDescriptor: The protocol declaring the associated type.
  /// - Returns: The associated type's metadata, or `nil` when this type does
  ///   not conform to that protocol or the protocol has no matching name.
  public func associatedType(
    named name: String,
    conformingTo protocolDescriptor: ProtocolDescriptor
  ) -> Metadata? {
    guard let witnessTable = swift_conformsToProtocol(
      metadata: self,
      protocol: protocolDescriptor
    ) else {
      return nil
    }

    return protocolDescriptor.associatedTypeWitness(
      named: name,
      conformingType: self,
      witnessTable: witnessTable
    )
  }
}
