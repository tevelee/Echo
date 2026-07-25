//
//  WitnessTable.swift
//  Echo
//
//  Created by Alejandro Alonso
//  Copyright © 2020 - 2021 Alejandro Alonso. All rights reserved.
//

/// In its simpliest form, a witness table is simply a table of function pointers
/// that fulfill the requirements a protocol imposes. Witness tables instruct
/// exactly how a type conforms to a protocol and the functions needed to
/// satisy a protocol requirement.
///
/// - Note: While witness tables in the form provided are ABI stable (on some
///         platforms), its runtime layout is not ABI stable. The only ABI
///         stable portion of a witness table is the conformance descriptor
///         pointer at the beginning, the rest of the layout is completely
///         dependent on the protocol and runtime being used.
///
/// ABI Stability: Stable since the following
///
///     | macOS | iOS/tvOS | watchOS | Linux | Windows |
///     |-------|----------|---------|-------|---------|
///     | 10.14 | 12.2     | 5.2     | NA    | NA      |
///
public struct WitnessTable: LayoutWrapper {
  typealias Layout = _WitnessTable

  /// The raw pointer to the witness table in memory.
  public let ptr: UnsafeRawPointer

  /// Initializes a witness table from a raw pointer.
  /// - Parameter ptr: A pointer to the witness table's memory layout.
  public init(ptr: UnsafeRawPointer) {
    self.ptr = ptr
  }

  /// The conformance descriptor that describes the protocol conformance
  /// relationship for whatever type this witness table is representing, and
  /// the protocol that type conforms to.
  public var conformanceDescriptor: ConformanceDescriptor {
    layout._conformance
  }
}

extension WitnessTable: Equatable {
  public static func == (lhs: WitnessTable, rhs: WitnessTable) -> Bool {
    lhs.ptr == rhs.ptr
  }
}

/// A protocol witness table whose entries use relative pointers.
///
/// Some Swift runtime builds use this representation to reduce relocation
/// overhead. Its requirement entries remain protocol-specific and opaque, but
/// the leading conformance descriptor is always inspectable.
///
/// Do not pass a `RelativeWitnessTable` to APIs expecting `WitnessTable`:
/// their entries have different physical representations.
public struct RelativeWitnessTable: LayoutWrapper {
  typealias Layout = _RelativeWitnessTable

  /// The raw pointer to the relative witness table in memory.
  public let ptr: UnsafeRawPointer

  /// Initializes a relative witness table from a raw pointer.
  /// - Parameter ptr: A pointer to the table's memory layout.
  public init(ptr: UnsafeRawPointer) {
    self.ptr = ptr
  }

  /// The conformance descriptor that describes this protocol conformance.
  public var conformanceDescriptor: ConformanceDescriptor {
    let field = ptr + MemoryLayout<_RelativeWitnessTable>.offset(
      of: \._conformance
    )!
    return ConformanceDescriptor(
      ptr: layout._conformance.address(from: field)
    )
  }
}

extension RelativeWitnessTable: Equatable {
  public static func == (lhs: RelativeWitnessTable, rhs: RelativeWitnessTable) -> Bool {
    lhs.ptr == rhs.ptr
  }
}

struct _WitnessTable {
  let _conformance: ConformanceDescriptor
}

struct _RelativeWitnessTable {
  let _conformance: RelativeIndirectablePointer<_ConformanceDescriptor>
}
