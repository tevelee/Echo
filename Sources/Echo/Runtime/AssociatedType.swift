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

  /// Resolves the witness table proving that an associated type conforms to
  /// `targetProtocol` for a particular conformance.
  ///
  /// The protocol requirement signature and associated-conformance access
  /// requirements must have a one-to-one ordering. When a refining protocol
  /// does not meet that ABI shape, this method fails closed with `nil`.
  public func associatedConformanceWitness(
    ofAssociatedType associatedTypeName: String,
    to targetProtocol: ProtocolDescriptor,
    conformingType: Metadata,
    witnessTable: WitnessTable
  ) -> WitnessTable? {
    guard let associatedType = associatedTypeWitness(
      named: associatedTypeName,
      conformingType: conformingType,
      witnessTable: witnessTable
    ) else {
      return nil
    }

    let protocolRequirements = requirements
    guard let firstRequirement = protocolRequirements.first else { return nil }
    let requirementBase = firstRequirement.ptr
      - MemoryLayout<_ProtocolRequirement>.size

    let signatureConformances = requirementSignature.filter {
      $0.flags.kind == .protocol
    }
    let accessRequirements = protocolRequirements.filter {
      $0.flags.kind == .associatedConformanceAccessFunction
    }
    guard signatureConformances.count == accessRequirements.count,
          let index = signatureConformances.firstIndex(where: {
            $0.protocol == targetProtocol
          })
    else {
      return nil
    }

    guard let pointer = echo_swift_getAssociatedConformanceWitness(
      witnessTable.ptr,
      conformingType.ptr,
      associatedType.ptr,
      requirementBase,
      accessRequirements[index].ptr
    ) else {
      return nil
    }
    return WitnessTable(ptr: pointer)
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

  /// Resolves the witness table proving one of this type's associated types
  /// conforms to another protocol.
  public func associatedConformance(
    ofAssociatedType associatedTypeName: String,
    to targetProtocol: ProtocolDescriptor,
    conformingTo protocolDescriptor: ProtocolDescriptor
  ) -> WitnessTable? {
    guard let witnessTable = swift_conformsToProtocol(
      metadata: self,
      protocol: protocolDescriptor
    ) else {
      return nil
    }

    return protocolDescriptor.associatedConformanceWitness(
      ofAssociatedType: associatedTypeName,
      to: targetProtocol,
      conformingType: self,
      witnessTable: witnessTable
    )
  }
}
