//
//  ExistentialMetadata.swift
//  Echo
//
//  Created by Alejandro Alonso
//  Copyright © 2019 - 2021 Alejandro Alonso. All rights reserved.
//

/// The metadata structure that represents some existential type, mainly
/// `protocol`s, in Swift.
///
/// ABI Stability: Unstable across all platforms
///
///     | macOS | iOS/tvOS | watchOS | Linux | Windows |
///     |-------|----------|---------|-------|---------|
///     | NA    | NA       | NA      | NA    | NA      |
///
public struct ExistentialMetadata: Metadata, LayoutWrapper {
  typealias Layout = _ExistentialMetadata
  
  /// Backing existential metadata pointer.
  public let ptr: UnsafeRawPointer
  
  /// The flags specific to existential metadata.
  public var flags: Flags {
    layout._flags
  }
  
  /// The number of protocols that compose this existential type.
  public var numProtocols: Int {
    Int(layout._numProtos)
  }
  
  /// The superclass type that this existential is constrained to, if any.
  public var superclass: Any.Type? {
    guard flags.hasSuperclassConstraint else { return nil }
    
    return trailing.load(as: Any.Type.self)
  }
  
  /// The superclass metadata that this existential is constrained to, if any.
  public var superclassMetadata: Metadata? {
    superclass.map { reflect($0) }
  }
  
  /// An array of protocol references that make up this existential.
  ///
  /// Swift stores both native Swift protocol descriptors and Objective-C
  /// protocol objects in this trailing array. `protocolReferences` preserves
  /// that discriminator, so it is safe for existentials such as
  /// `any NSObjectProtocol` as well as ordinary Swift protocol compositions.
  public var protocolReferences: [ExistentialProtocolReference] {
    Array(unsafeUninitializedCapacity: numProtocols) {
      var start = trailing

      if flags.hasSuperclassConstraint {
        start = start.offset(of: 1)
      }

      for index in 0 ..< numProtocols {
        $0[index] = ExistentialProtocolReference(
          rawValue: start.load(
            fromByteOffset: index * MemoryLayout<UInt>.stride,
            as: UInt.self
          )
        )
      }

      $1 = numProtocols
    }
  }

  /// Native Swift protocol descriptors that make up this existential.
  ///
  /// This compatibility projection intentionally omits Objective-C protocol
  /// references. Use `protocolReferences` when the existential may include
  /// Objective-C protocols.
  public var protocols: [ProtocolDescriptor] {
    protocolReferences.compactMap(\.swiftProtocol)
  }
}

extension ExistentialMetadata: Equatable {}

/// A protocol constraint recorded in simple existential metadata.
///
/// Swift uses the low bit of the stored pointer to distinguish a native Swift
/// protocol descriptor from an Objective-C protocol object. The Objective-C
/// object is exposed as an address because its full layout belongs to the
/// Objective-C runtime.
public struct ExistentialProtocolReference: Equatable, Sendable {
  /// The pointer and discriminator bit as stored by the Swift runtime.
  public let rawValue: UInt

  /// Creates a reference from its ABI representation.
  public init(rawValue: UInt) {
    self.rawValue = rawValue
  }

  /// The runtime kind of the referenced protocol.
  public var kind: Kind {
    #if canImport(ObjectiveC)
    rawValue & 0x1 == 0 ? .swift : .objc
    #else
    .swift
    #endif
  }

  /// The native Swift protocol descriptor, when this is a Swift protocol.
  public var swiftProtocol: ProtocolDescriptor? {
    guard kind == .swift, let pointer = UnsafeRawPointer(bitPattern: rawValue) else {
      return nil
    }
    return ProtocolDescriptor(ptr: pointer)
  }

  /// The Objective-C protocol object's address, when this is an Objective-C
  /// protocol. The address is owned and managed by the Objective-C runtime.
  public var objcProtocolAddress: UnsafeRawPointer? {
    guard kind == .objc else { return nil }
    return UnsafeRawPointer(bitPattern: rawValue & ~UInt(0x1))
  }

  /// The protocol's runtime name.
  public var name: String? {
    switch kind {
    case .swift:
      return swiftProtocol?.name
    case .objc:
      guard let pointer = objcProtocolAddress else { return nil }
      let namePointer = pointer.load(fromByteOffset: MemoryLayout<UnsafeRawPointer>.stride, as: UnsafePointer<CChar>?.self)
      return namePointer.map(String.init(cString:))
    }
  }

  /// The dispatch strategy used by this protocol.
  public var dispatchStrategy: ProtocolDispatchStrategy {
    kind == .swift ? .swift : .objc
  }

  /// Whether method calls through this protocol require a Swift witness
  /// table.
  public var needsWitnessTable: Bool {
    kind == .swift
  }

  /// Whether this protocol is class-constrained.
  public var hasClassConstraint: Bool {
    switch kind {
    case .swift:
      return swiftProtocol?.protocolFlags.hasClassConstraint ?? false
    case .objc:
      return true
    }
  }

  /// The special runtime-known protocol kind, if this is a Swift protocol.
  public var specialProtocol: SpecialProtocol? {
    swiftProtocol?.protocolFlags.specialProtocol
  }

  /// Protocol kinds used by `ExistentialProtocolReference`.
  public enum Kind: Sendable {
    /// A native Swift protocol descriptor.
    case swift

    /// An Objective-C protocol object.
    case objc
  }
}

/// The method-dispatch ABI used by a protocol reference.
public enum ProtocolDispatchStrategy: UInt8, Sendable {
  /// Objective-C message dispatch.
  case objc = 0

  /// Swift witness-table dispatch.
  case swift = 1
}

struct _ExistentialMetadata {
  let _kind: Int
  let _flags: ExistentialMetadata.Flags
  let _numProtos: UInt32
}
