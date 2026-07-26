//
//  GenericContext.swift
//  Echo
//
//  Created by Alejandro Alonso
//  Copyright © 2019 - 2021 Alejandro Alonso. All rights reserved.
//

/// A generic context describes the generic information about some generic
/// context.
///
/// ABI Stability: Stable since the following
///
///     | macOS | iOS/tvOS | watchOS | Linux | Windows |
///     |-------|----------|---------|-------|---------|
///     | 10.14 | 12.2     | 5.2     | NA    | NA      |
///
public struct GenericContext: LayoutWrapper {
  typealias Layout = _GenericContextDescriptorHeader
  
  /// Backing generic context pointer.
  let ptr: UnsafeRawPointer
  
  /// The number of generic parameters this context has.
  public var numParams: Int {
    Int(layout._numParams)
  }
  
  /// The number of generic requirements this context has.
  public var numRequirements: Int {
    Int(layout._numRequirements)
  }
  
  /// The number of "key" generic parameters this context has.
  public var numKeyArguments: Int {
    Int(layout._numKeyArguments)
  }
  
  /// The number of "extra" generic parameters this context has.
  ///
  /// This value is always zero in current Swift ABIs. The storage formerly
  /// used for it now holds `descriptorFlags`.
  public var numExtraArguments: Int {
    0
  }
  
  /// The number of bytes the parameters take up.
  var parameterSize: Int {
    (-numParams & 3) + numParams
  }
  
  /// An array of all the generic parameters this context has.
  public var parameters: [GenericParameterDescriptor] {
    guard numParams > 0 else { return [] }

    return Array(unsafeUninitializedCapacity: numParams) {
      for i in 0 ..< numParams {
        let param = trailing.load(
          fromByteOffset: i * MemoryLayout<GenericParameterDescriptor>.stride,
          as: GenericParameterDescriptor.self
        )
        
        $0[i] = param
      }
      
      $1 = numParams
    }
  }
  
  /// The number of bytes the requirements take up.
  var requirementSize: Int {
    numRequirements * MemoryLayout<_GenericRequirementDescriptor>.size
  }
  
  /// An array of all the generic requirements this context has.
  public var requirements: [GenericRequirementDescriptor] {
    guard numRequirements > 0 else { return [] }

    return Array(unsafeUninitializedCapacity: numRequirements) {
      for i in 0 ..< numRequirements {
        let requirements = trailing + parameterSize
        let address = requirements.offset(
          of: i,
          as: _GenericRequirementDescriptor.self
        )
        
        $0[i] = GenericRequirementDescriptor(ptr: address)
      }
      
      $1 = numRequirements
    }
  }
  
  /// Number of bytes this generic context is.
  public var size: Int {
    let base = MemoryLayout<_GenericContextDescriptorHeader>.size
    return base + trailingLayout.size
  }

  /// Flags describing the trailing records carried by this generic context.
  public var descriptorFlags: GenericContextDescriptorFlags {
    GenericContextDescriptorFlags(bits: layout._numExtraArguments)
  }

  /// The pack-shape header for a variadic-generic context, if present.
  public var packShapeHeader: GenericPackShapeHeader? {
    guard let offset = trailingLayout.packShapeHeader else { return nil }
    return (trailing + offset).load(as: GenericPackShapeHeader.self)
  }

  /// Shape descriptors for each metadata or witness-table pack in this
  /// context. The ABI records one descriptor per pack, not per shape class.
  public var packShapeDescriptors: [GenericPackShapeDescriptor] {
    guard let offset = trailingLayout.packShapeDescriptors,
          let header = packShapeHeader
    else { return [] }

    return loadTrailing(
      from: offset,
      count: Int(header.numPacks),
      as: GenericPackShapeDescriptor.self
    )
  }

  /// The protocols with conditional requirements in this generic context.
  ///
  /// The presence of this record is controlled by
  /// `descriptorFlags.hasConditionalInvertedProtocols`. The individual
  /// requirement counts are cumulative and are available through
  /// `conditionalInvertedProtocolRequirementCounts`.
  public var conditionalInvertedProtocols: InvertibleProtocolSet? {
    guard let offset = trailingLayout.conditionalInvertedProtocols else {
      return nil
    }

    return InvertibleProtocolSet(bits: (trailing + offset).load(as: UInt16.self))
  }

  /// Cumulative requirement counts for each conditional inverted protocol.
  ///
  /// An empty array is returned when no conditional inverted-protocol record
  /// is present or its cumulative counts are invalid.
  public var conditionalInvertedProtocolRequirementCounts: [UInt16] {
    guard let offset = trailingLayout.conditionalRequirementCounts,
          let protocols = conditionalInvertedProtocols
    else { return [] }

    return loadTrailing(
      from: offset,
      count: protocols.bits.nonzeroBitCount,
      as: UInt16.self
    )
  }

  /// Requirements associated with `conditionalInvertedProtocols`.
  ///
  /// The final cumulative count determines the number of records. Invalid
  /// cumulative counts are treated as no readable trailing requirements.
  public var conditionalInvertedProtocolRequirements: [GenericRequirementDescriptor] {
    guard let offset = trailingLayout.conditionalRequirements else { return [] }

    return Array(unsafeUninitializedCapacity: trailingLayout.conditionalRequirementCount) {
      for index in 0 ..< trailingLayout.conditionalRequirementCount {
        let address = (trailing + offset).advanced(
          by: index * MemoryLayout<_GenericRequirementDescriptor>.stride
        )
        $0[index] = GenericRequirementDescriptor(ptr: address)
      }
      $1 = trailingLayout.conditionalRequirementCount
    }
  }

  /// The header for value generic parameters, if the context contains them.
  public var genericValueHeader: GenericValueHeader? {
    guard let offset = trailingLayout.genericValueHeader else { return nil }
    return (trailing + offset).load(as: GenericValueHeader.self)
  }

  /// Descriptors for value generic parameters.
  public var genericValueDescriptors: [GenericValueDescriptor] {
    guard let offset = trailingLayout.genericValueDescriptors,
          genericValueHeader != nil
    else { return [] }

    return loadTrailing(
      from: offset,
      count: trailingLayout.genericValueDescriptorCount,
      as: GenericValueDescriptor.self
    )
  }

  private func loadTrailing<T>(from offset: Int, count: Int, as: T.Type) -> [T] {
    guard count > 0 else { return [] }

    return Array(unsafeUninitializedCapacity: count) {
      for index in 0 ..< count {
        $0[index] = (trailing + offset).load(
          fromByteOffset: index * MemoryLayout<T>.stride,
          as: T.self
        )
      }
      $1 = count
    }
  }

  private var trailingLayout: TrailingLayout {
    var cursor = parameterSize + requirementSize
    var packShapeHeader: Int?
    var packShapeDescriptors: Int?
    var conditionalInvertedProtocols: Int?
    var conditionalRequirementCounts: Int?
    var conditionalRequirements: Int?
    var conditionalRequirementCount = 0
    var genericValueHeader: Int?
    var genericValueDescriptors: Int?
    var genericValueDescriptorCount = 0

    if descriptorFlags.hasTypePacks {
      cursor = aligned(cursor, for: GenericPackShapeHeader.self)
      packShapeHeader = cursor
      let header = (trailing + cursor).load(as: GenericPackShapeHeader.self)
      cursor += MemoryLayout<GenericPackShapeHeader>.stride

      cursor = aligned(cursor, for: GenericPackShapeDescriptor.self)
      packShapeDescriptors = cursor
      cursor += Int(header.numPacks) * MemoryLayout<GenericPackShapeDescriptor>.stride
    }

    if descriptorFlags.hasConditionalInvertedProtocols {
      cursor = aligned(cursor, for: UInt16.self)
      conditionalInvertedProtocols = cursor
      let protocols = (trailing + cursor).load(as: UInt16.self)
      cursor += MemoryLayout<UInt16>.stride

      let countCount = protocols.nonzeroBitCount
      cursor = aligned(cursor, for: UInt16.self)
      conditionalRequirementCounts = cursor
      let counts = loadTrailing(from: cursor, count: countCount, as: UInt16.self)
      cursor += countCount * MemoryLayout<UInt16>.stride

      guard counts.indices.dropFirst().allSatisfy({ counts[$0 - 1] <= counts[$0] }) else {
        return TrailingLayout(size: cursor)
      }

      conditionalRequirementCount = Int(counts.last ?? 0)
      cursor = aligned(cursor, for: _GenericRequirementDescriptor.self)
      conditionalRequirements = cursor
      cursor += conditionalRequirementCount * MemoryLayout<_GenericRequirementDescriptor>.stride
    }

    if descriptorFlags.hasValues {
      cursor = aligned(cursor, for: GenericValueHeader.self)
      genericValueHeader = cursor
      let header = (trailing + cursor).load(as: GenericValueHeader.self)
      cursor += MemoryLayout<GenericValueHeader>.stride

      guard let descriptorCount = Int(exactly: header.numValues) else {
        return TrailingLayout(size: cursor)
      }

      cursor = aligned(cursor, for: GenericValueDescriptor.self)
      genericValueDescriptors = cursor
      genericValueDescriptorCount = descriptorCount
      cursor += descriptorCount * MemoryLayout<GenericValueDescriptor>.stride
    }

    return TrailingLayout(
      packShapeHeader: packShapeHeader,
      packShapeDescriptors: packShapeDescriptors,
      conditionalInvertedProtocols: conditionalInvertedProtocols,
      conditionalRequirementCounts: conditionalRequirementCounts,
      conditionalRequirements: conditionalRequirements,
      conditionalRequirementCount: conditionalRequirementCount,
      genericValueHeader: genericValueHeader,
      genericValueDescriptors: genericValueDescriptors,
      genericValueDescriptorCount: genericValueDescriptorCount,
      size: cursor
    )
  }

  private func aligned<T>(_ offset: Int, for: T.Type) -> Int {
    let alignment = MemoryLayout<T>.alignment
    return (offset + alignment - 1) & -alignment
  }

  private struct TrailingLayout {
    var packShapeHeader: Int?
    var packShapeDescriptors: Int?
    var conditionalInvertedProtocols: Int?
    var conditionalRequirementCounts: Int?
    var conditionalRequirements: Int?
    var conditionalRequirementCount: Int = 0
    var genericValueHeader: Int?
    var genericValueDescriptors: Int?
    var genericValueDescriptorCount: Int = 0
    var size: Int

    init(size: Int) {
      self.size = size
    }

    init(
      packShapeHeader: Int?,
      packShapeDescriptors: Int?,
      conditionalInvertedProtocols: Int?,
      conditionalRequirementCounts: Int?,
      conditionalRequirements: Int?,
      conditionalRequirementCount: Int,
      genericValueHeader: Int?,
      genericValueDescriptors: Int?,
      genericValueDescriptorCount: Int,
      size: Int
    ) {
      self.packShapeHeader = packShapeHeader
      self.packShapeDescriptors = packShapeDescriptors
      self.conditionalInvertedProtocols = conditionalInvertedProtocols
      self.conditionalRequirementCounts = conditionalRequirementCounts
      self.conditionalRequirements = conditionalRequirements
      self.conditionalRequirementCount = conditionalRequirementCount
      self.genericValueHeader = genericValueHeader
      self.genericValueDescriptors = genericValueDescriptors
      self.genericValueDescriptorCount = genericValueDescriptorCount
      self.size = size
    }
  }
}

/// Flags describing modern generic-context trailing records.
public struct GenericContextDescriptorFlags {
  /// Flags as represented in bits.
  public let bits: UInt16

  /// Whether the context contains at least one `each` type parameter.
  public var hasTypePacks: Bool {
    bits & 0x1 != 0
  }

  /// Whether the context carries conditional inverted-protocol requirements.
  public var hasConditionalInvertedProtocols: Bool {
    bits & 0x2 != 0
  }

  /// Whether the context contains at least one value generic parameter.
  public var hasValues: Bool {
    bits & 0x4 != 0
  }
}

/// Header preceding a generic context's pack-shape descriptors.
public struct GenericPackShapeHeader {
  /// Number of parameter and conformance-requirement packs.
  public let numPacks: UInt16

  /// Number of equivalence classes in the same-shape relation.
  public let numShapeClasses: UInt16
}

/// The kind of generic argument pack described by a pack-shape descriptor.
public enum GenericPackKind: UInt16 {
  case metadata = 0
  case witnessTable = 1
}

/// Describes one metadata or witness-table pack and its shape equivalence class.
public struct GenericPackShapeDescriptor {
  private let rawKind: UInt16

  /// Index of this pack in the generic arguments layout.
  public let index: UInt16

  /// Same-shape equivalence class for this pack.
  public let shapeClass: UInt16

  private let unused: UInt16

  /// The kind of pack, or `nil` for an ABI kind Echo does not yet understand.
  public var kind: GenericPackKind? {
    GenericPackKind(rawValue: rawKind)
  }
}

/// Header preceding the descriptors for value generic parameters.
public struct GenericValueHeader {
  /// Number of value generic parameters in the generic signature.
  public let numValues: UInt32
}

/// The representation of a value generic parameter.
public enum GenericValueType: UInt32 {
  /// An integer value generic parameter.
  case int = 0
}

/// Describes one value generic parameter.
public struct GenericValueDescriptor {
  private let rawType: UInt32

  /// The parameter representation, or `nil` for an ABI value kind Echo does
  /// not yet understand.
  public var type: GenericValueType? {
    GenericValueType(rawValue: rawType)
  }
}

/// This descriptor describes any generic requirement in either a generic
/// context or in a protocol's requirement signature.
///
/// ABI Stability: Stable since the following
///
///     | macOS | iOS/tvOS | watchOS | Linux | Windows |
///     |-------|----------|---------|-------|---------|
///     | 10.14 | 12.2     | 5.2     | NA    | NA      |
///
public struct GenericRequirementDescriptor: LayoutWrapper {
  typealias Layout = _GenericRequirementDescriptor
  
  /// Backing generic requirement descriptor pointer.
  let ptr: UnsafeRawPointer
  
  /// The flags that describe this generic requirement.
  public var flags: Flags {
    layout._flags
  }
  
  /// The mangled name for this requirement's parameter.
  public var paramMangledName: UnsafeRawPointer {
    address(for: \._param)
  }
  
  /// If this requirement is a same-type, base-class, or same-shape
  /// requirement, this is the mangled name for the constrained type or pack.
  public var mangledTypeName: UnsafeRawPointer {
    assert(
      flags.kind == .sameType || flags.kind == .baseClass || flags.kind == .sameShape
    )
    let addr = address(for: \._requirement)
    return addr.relativeDirectAddress(as: CChar.self)
  }
  
  /// If this requirement is a protocol, this is the protocol descriptor to
  /// said protocol being constrained.
  public var `protocol`: ProtocolDescriptor {
    assert(flags.kind == .protocol)
    let addr = address(for: \._requirement)
    let ptr = SignedPointer<ProtocolDescriptor>(
      ptr: addr.relativeIndirectableIntPairAddress(
        as: _ProtocolDescriptor.self,
        and: UInt8.self
      )
    ).signed
    return ProtocolDescriptor(ptr: ptr!)
  }

  /// If this is a same-conformance requirement, the conformance descriptor
  /// that the parameter is constrained to use.
  public var conformance: ConformanceDescriptor {
    precondition(flags.kind == .sameConformance)
    let field = address(for: \._requirement)
    let reference = RelativeIndirectablePointer<_ConformanceDescriptor>(
      offset: layout._requirement
    )
    return ConformanceDescriptor(ptr: reference.address(from: field))
  }
  
  /// If this requirement is some layout (currently can only be a class),
  /// this is the kind of layout that's being constrained.
  public var layoutKind: GenericRequirementLayoutKind {
    assert(flags.kind == .layout)
    return GenericRequirementLayoutKind(rawValue: UInt32(layout._requirement))!
  }

  /// The capability protocols inverted by this requirement, such as
  /// `Copyable` for a `~Copyable` generic parameter.
  public var invertedProtocols: InvertibleProtocolSet {
    precondition(flags.kind == .invertedProtocols)
    return InvertibleProtocolSet(
      bits: UInt16(truncatingIfNeeded: UInt32(bitPattern: layout._requirement) >> 16)
    )
  }

  /// The generic parameter affected by `invertedProtocols`.
  ///
  /// `UInt16.max` means the constraint applies to the requirement subject
  /// rather than a direct generic parameter.
  public var invertedProtocolsGenericParameterIndex: UInt16 {
    precondition(flags.kind == .invertedProtocols)
    return UInt16(truncatingIfNeeded: layout._requirement)
  }
}

/// A type generic context is an extension of a generic context for contexts
/// that define some type in Swift. Currently that includes structs, classes,
/// and enums. While protocols do define a type, they aren't considered type
/// contexts.
///
/// ABI Stability: Stable since the following
///
///     | macOS | iOS/tvOS | watchOS | Linux | Windows |
///     |-------|----------|---------|-------|---------|
///     | 10.14 | 12.2     | 5.2     | NA    | NA      |
///
public struct TypeGenericContext: LayoutWrapper {
  typealias Layout = _TypeGenericContextDescriptorHeader
  
  /// Backing type generic context pointer.
  let ptr: UnsafeRawPointer
  
  /// Grab the base context.
  var baseContext: GenericContext {
    GenericContext(ptr: address(for: \._base))
  }
  
  /// The number of generic parameters this context has.
  public var numParams: Int {
    baseContext.numParams
  }
  
  /// The number of generic requirements this context has.
  public var numRequirements: Int {
    baseContext.numRequirements
  }
  
  /// The number of "key" generic parameters this context has.
  public var numKeyArguments: Int {
    baseContext.numKeyArguments
  }
  
  /// The number of "extra" generic parameters this context has.
  public var numExtraArguments: Int {
    baseContext.numExtraArguments
  }
  
  /// An array of all the generic parameters this context has.
  public var parameters: [GenericParameterDescriptor] {
    baseContext.parameters
  }
  
  /// An array of all the generic requirements this context has.
  public var requirements: [GenericRequirementDescriptor] {
    baseContext.requirements
  }
  
  /// The instantiation pattern for this type generic context.
  public var genericMetadataPattern: GenericMetadataPattern {
    let ptr = address(for: \._defaultInstantiationPattern)
    return GenericMetadataPattern(ptr: ptr)
  }
  
  /// Number of bytes this type generic context is.
  public var size: Int {
    let base = baseContext.size
    let type = MemoryLayout<_TypeGenericContextDescriptorHeader>.size -
               MemoryLayout<_GenericContextDescriptorHeader>.size
    return base + type
  }
}

/// An instantiation pattern for metadata.
///
/// ABI Stability: Stable since the following
///
///     | macOS | iOS/tvOS | watchOS | Linux | Windows |
///     |-------|----------|---------|-------|---------|
///     | 10.14 | 12.2     | 5.2     | NA    | NA      |
///
public struct GenericMetadataPattern: LayoutWrapper {
  typealias Layout = _GenericMetadataPattern
  
  /// Backing GenericMetadataPattern pointer.
  let ptr: UnsafeRawPointer

  /// The runtime entry point that instantiates metadata from this pattern.
  ///
  /// The function has a runtime-private calling convention. Echo exposes its
  /// address for inspection only; clients must not invoke it.
  public var instantiationFunction: UnsafeRawPointer? {
    let field = ptr + MemoryLayout<_GenericMetadataPattern>.offset(
      of: \._instantiationFunction
    )!
    let reference = layout._instantiationFunction
    guard reference.isNull == false else { return nil }
    return reference.address(from: field)
  }

  /// The runtime entry point that completes metadata instantiated from this
  /// pattern, if the instantiator does not produce complete metadata itself.
  ///
  /// The function has a runtime-private calling convention. Echo exposes its
  /// address for inspection only; clients must not invoke it.
  public var completionFunction: UnsafeRawPointer? {
    let field = ptr + MemoryLayout<_GenericMetadataPattern>.offset(
      of: \._completionFunction
    )!
    let reference = layout._completionFunction
    guard reference.isNull == false else { return nil }
    return reference.address(from: field)
  }
  
  /// The flags that represent this instantiation pattern.
  public var flags: Flags {
    layout._flags
  }
}

/// A typed generic-metadata pattern for structs and enums.
public struct GenericValueMetadataPattern: LayoutWrapper {
  typealias Layout = _GenericValueMetadataPattern

  /// Backing generic value metadata pattern pointer.
  let ptr: UnsafeRawPointer

  /// The common instantiation pattern header.
  public var metadataPattern: GenericMetadataPattern {
    GenericMetadataPattern(ptr: ptr)
  }

  /// The value-witness-table pattern selected for instantiated metadata, if
  /// the ABI record carries one. The pointer is runtime-private and is exposed
  /// for inspection only.
  public var valueWitnessTablePattern: UnsafeRawPointer? {
    let field = ptr + MemoryLayout<_GenericValueMetadataPattern>.offset(
      of: \._valueWitnesses
    )!
    let reference = layout._valueWitnesses
    guard reference.isNull == false else { return nil }
    return reference.address(from: field)
  }

  /// The extra-data copy pattern, if this generic value pattern carries one.
  public var extraDataPattern: GenericMetadataPartialPattern? {
    guard metadataPattern.flags.hasExtraDataPattern else { return nil }
    return GenericMetadataPartialPattern(
      ptr: ptr + MemoryLayout<_GenericValueMetadataPattern>.size
    )
  }
}

/// A typed generic-metadata pattern for classes.
public struct GenericClassMetadataPattern: LayoutWrapper {
  typealias Layout = _GenericClassMetadataPattern

  /// Backing generic class metadata pattern pointer.
  let ptr: UnsafeRawPointer

  /// The common instantiation pattern header.
  public var metadataPattern: GenericMetadataPattern {
    GenericMetadataPattern(ptr: ptr)
  }

  /// The runtime-private heap-destroyer entry point. It is exposed for
  /// inspection only and must not be invoked by clients.
  public var destroyFunction: UnsafeRawPointer? {
    functionAddress(for: \._destroy)
  }

  /// The runtime-private instance-variable destroyer entry point, if one was
  /// emitted. It is exposed for inspection only and must not be invoked by
  /// clients.
  public var ivarDestroyer: UnsafeRawPointer? {
    functionAddress(for: \._ivarDestroyer)
  }

  /// Class flags applied to metadata instantiated from this pattern.
  public var flags: ClassMetadata.Flags {
    layout._flags
  }

  /// The offset, in words, of Objective-C class RO data in the extra-data
  /// pattern. This is meaningful only for Objective-C-interoperable runtimes.
  public var classRODataOffset: UInt16 {
    layout._classRODataOffset
  }

  /// The offset, in words, of the Objective-C metaclass object in the
  /// extra-data pattern. This is meaningful only for Objective-C-interoperable
  /// runtimes.
  public var metaclassObjectOffset: UInt16 {
    layout._metaclassObjectOffset
  }

  /// The offset, in words, of Objective-C metaclass RO data in the extra-data
  /// pattern. This is meaningful only for Objective-C-interoperable runtimes.
  public var metaclassRODataOffset: UInt16 {
    layout._metaclassRODataOffset
  }

  /// The extra-data copy pattern, if this generic class pattern carries one.
  public var extraDataPattern: GenericMetadataPartialPattern? {
    guard metadataPattern.flags.hasExtraDataPattern else { return nil }
    return GenericMetadataPartialPattern(
      ptr: ptr + MemoryLayout<_GenericClassMetadataPattern>.size
    )
  }

  /// The immediate-members copy pattern, if this generic class pattern carries
  /// one.
  public var immediateMembersPattern: GenericMetadataPartialPattern? {
    guard metadataPattern.flags.classHasImmediateMembersPattern else {
      return nil
    }

    let offset = MemoryLayout<_GenericClassMetadataPattern>.size
      + (metadataPattern.flags.hasExtraDataPattern
        ? MemoryLayout<_GenericMetadataPartialPattern>.stride
        : 0)
    return GenericMetadataPartialPattern(ptr: ptr + offset)
  }

  private func functionAddress(
    for field: KeyPath<_GenericClassMetadataPattern, RelativeDirectPointer<UnsafeRawPointer>>
  ) -> UnsafeRawPointer? {
    let address = ptr + MemoryLayout<_GenericClassMetadataPattern>.offset(of: field)!
    let reference = layout[keyPath: field]
    guard reference.isNull == false else { return nil }
    return reference.address(from: address)
  }
}

/// A compact relative copy pattern embedded in a typed generic metadata
/// pattern.
public struct GenericMetadataPartialPattern: LayoutWrapper {
  typealias Layout = _GenericMetadataPartialPattern

  /// Backing partial pattern pointer.
  let ptr: UnsafeRawPointer

  /// The bytes copied into the instantiated metadata. The pattern is
  /// runtime-private data and is exposed for inspection only.
  public var pattern: UnsafeRawPointer? {
    let field = ptr + MemoryLayout<_GenericMetadataPartialPattern>.offset(
      of: \._pattern
    )!
    let reference = layout._pattern
    guard reference.isNull == false else { return nil }
    return reference.address(from: field)
  }

  /// The destination offset, in machine words, for `pattern`.
  public var offsetInWords: UInt16 {
    layout._offsetInWords
  }

  /// The number of machine words copied from `pattern`.
  public var sizeInWords: UInt16 {
    layout._sizeInWords
  }
}

struct _GenericContextDescriptorHeader {
  let _numParams: UInt16
  let _numRequirements: UInt16
  let _numKeyArguments: UInt16
  let _numExtraArguments: UInt16
}

struct _GenericRequirementDescriptor {
  let _flags: GenericRequirementDescriptor.Flags
  let _param: RelativeDirectPointer<CChar>
  // This field is a union which represents the type of requirement
  // that this parameter is constrained to. It is represented by the following:
  // 1. Same type requirement (RelativeDirectPointer<CChar>)
  // 2. Protocol requirement (RelativeIndirectablePointerIntPair<ProtocolDescriptor, Bool>)
  // 3. Conformance requirement (RelativeIndirectablePointer<ConformanceDescriptor>)
  // 4. Layout requirement (LayoutKind)
  let _requirement: Int32
}

struct _TypeGenericContextDescriptorHeader {
  // Private data for the runtime only.
  let _instantiationCache: RelativeDirectPointer<UnsafeRawPointer>
  let _defaultInstantiationPattern: RelativeDirectPointer<_GenericMetadataPattern>
  let _base: _GenericContextDescriptorHeader
}

struct _GenericMetadataPattern {
  let _instantiationFunction: RelativeDirectPointer<UnsafeRawPointer>
  let _completionFunction: RelativeDirectPointer<UnsafeRawPointer>
  let _flags: GenericMetadataPattern.Flags
}

struct _GenericValueMetadataPattern {
  let _base: _GenericMetadataPattern
  let _valueWitnesses: RelativeIndirectablePointer<UnsafeRawPointer>
}

struct _GenericClassMetadataPattern {
  let _base: _GenericMetadataPattern
  let _destroy: RelativeDirectPointer<UnsafeRawPointer>
  let _ivarDestroyer: RelativeDirectPointer<UnsafeRawPointer>
  let _flags: ClassMetadata.Flags
  let _classRODataOffset: UInt16
  let _metaclassObjectOffset: UInt16
  let _metaclassRODataOffset: UInt16
  let _reserved: UInt16
}

struct _GenericMetadataPartialPattern {
  let _pattern: RelativeDirectPointer<UnsafeRawPointer>
  let _offsetInWords: UInt16
  let _sizeInWords: UInt16
}
