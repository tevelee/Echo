//
//  ExtendedExistentialMetadata.swift
//  Echo
//
//  Copyright © 2026 Echo contributors.
//

/// Metadata for a constrained existential such as `any Collection<Int>`.
///
/// Extended existential metadata is runtime-private and may gain new shape
/// records in future Swift releases. Echo exposes the stable leading shape and
/// its documented trailing signature records without assuming an existential
/// has the legacy protocol-composition layout.
public struct ExtendedExistentialMetadata: Metadata, LayoutWrapper,
  ExistentialTypeMetadata {
  typealias Layout = _ExtendedExistentialMetadata

  /// Backing extended existential metadata pointer.
  public let ptr: UnsafeRawPointer

  /// The shape describing this existential's requirement and generalization
  /// signatures.
  public var shape: ExtendedExistentialTypeShape {
    ExtendedExistentialTypeShape(ptr: layout._shape.signed)
  }

  /// The raw generalization arguments following the shape pointer.
  ///
  /// Their interpretation follows the shape's generic argument layout and can
  /// include metadata, witness tables, packs, and values. They are intentionally
  /// exposed as raw words rather than being misidentified as metatypes.
  public var generalizationArguments: [UnsafeRawPointer] {
    Array(unsafeUninitializedCapacity: shape.generalizationArgumentCount) {
      for index in 0 ..< shape.generalizationArgumentCount {
        $0[index] = trailing.load(
          fromByteOffset: index * MemoryLayout<UnsafeRawPointer>.stride,
          as: UnsafeRawPointer.self
        )
      }
      $1 = shape.generalizationArgumentCount
    }
  }
}

extension ExtendedExistentialMetadata: Equatable {}

/// Common metadata surface for legacy and constrained existential types.
public protocol ExistentialTypeMetadata: Metadata {}

extension ExistentialMetadata: ExistentialTypeMetadata {}

/// The shape of a constrained existential type.
public struct ExtendedExistentialTypeShape: LayoutWrapper {
  typealias Layout = _ExtendedExistentialTypeShape

  /// Backing shape pointer.
  let ptr: UnsafeRawPointer

  /// Flags describing the existential representation and its optional records.
  public var flags: Flags {
    layout._flags
  }

  /// The mangled existential type expression stored in the shape.
  public var mangledTypeName: UnsafeRawPointer {
    address(for: \._existentialType).relativeDirectAddress(as: CChar.self)
  }

  /// The number of parameters in the requirement signature.
  public var requirementParameterCount: Int {
    Int(layout._requirementSignature._numParams)
  }

  /// The number of requirements in the requirement signature.
  public var requirementCount: Int {
    Int(layout._requirementSignature._numRequirements)
  }

  /// The generalization signature, if this existential specializes one.
  public var generalizationSignature: GenericSignatureHeader? {
    guard flags.hasGeneralizationSignature else { return nil }
    return (ptr + MemoryLayout<_ExtendedExistentialTypeShape>.size)
      .load(as: GenericSignatureHeader.self)
  }

  /// The number of generalization arguments in words.
  public var generalizationArgumentCount: Int {
    Int(generalizationSignature?.numKeyArguments ?? 0)
  }

  /// Explicit requirement-signature parameters. When
  /// `hasImplicitRequirementSignatureParameters` is true, the Swift runtime
  /// supplies canonical implicit descriptors instead and this array is empty.
  public var requirementParameters: [GenericParameterDescriptor] {
    loadParameters(at: trailingSignatureOffset, count: requirementParameterCount,
                   isImplicit: flags.hasImplicitRequirementSignatureParameters)
  }

  /// Explicit generalization-signature parameters.
  public var generalizationParameters: [GenericParameterDescriptor] {
    guard let signature = generalizationSignature else { return [] }
    let offset = trailingSignatureOffset
      + (flags.hasImplicitRequirementSignatureParameters ? 0 : requirementParameterCount)
    return loadParameters(at: offset, count: Int(signature.numParams),
                          isImplicit: flags.hasImplicitGeneralizationSignatureParameters)
  }

  /// Requirement-signature requirements.
  public var requirementRequirements: [GenericRequirementDescriptor] {
    loadRequirements(at: requirementRequirementsOffset, count: requirementCount)
  }

  /// Generalization-signature requirements.
  public var generalizationRequirements: [GenericRequirementDescriptor] {
    guard let signature = generalizationSignature else { return [] }
    let offset = requirementRequirementsOffset
      + requirementCount * MemoryLayout<_GenericRequirementDescriptor>.stride
    return loadRequirements(at: offset, count: Int(signature.numRequirements))
  }

  /// The optional mangled type subexpression, if the shape stores one.
  public var typeExpressionMangledName: UnsafeRawPointer? {
    guard flags.hasTypeExpression else { return nil }
    return (ptr + typeExpressionOffset).relativeDirectAddress(as: CChar.self)
  }

  /// A suggested value witness table for the existential, if the shape stores
  /// one. This is a read-only layout suggestion, not a request to copy values.
  public var suggestedValueWitnessTable: ValueWitnessTable? {
    guard flags.hasSuggestedValueWitnesses else { return nil }
    let field = ptr + suggestedValueWitnessTableOffset
    let pointer = RelativeIndirectablePointer<ValueWitnessTable>(
      offset: field.load(as: Int32.self)
    ).address(from: field)
    return ValueWitnessTable(ptr: pointer)
  }

  private var trailingSignatureOffset: Int {
    var offset = MemoryLayout<_ExtendedExistentialTypeShape>.size
    if flags.hasGeneralizationSignature {
      offset += MemoryLayout<GenericSignatureHeader>.stride
    }
    if flags.hasTypeExpression {
      offset += MemoryLayout<Int32>.stride
    }
    if flags.hasSuggestedValueWitnesses {
      offset += MemoryLayout<Int32>.stride
    }
    return offset
  }

  private var typeExpressionOffset: Int {
    MemoryLayout<_ExtendedExistentialTypeShape>.size
      + (flags.hasGeneralizationSignature ? MemoryLayout<GenericSignatureHeader>.stride : 0)
  }

  private var suggestedValueWitnessTableOffset: Int {
    typeExpressionOffset + (flags.hasTypeExpression ? MemoryLayout<Int32>.stride : 0)
  }

  private var requirementRequirementsOffset: Int {
    let parameterEnd = trailingSignatureOffset
      + (flags.hasImplicitRequirementSignatureParameters ? 0 : requirementParameterCount)
      + (flags.hasImplicitGeneralizationSignatureParameters
        ? 0
        : Int(generalizationSignature?.numParams ?? 0))
    let alignment = MemoryLayout<_GenericRequirementDescriptor>.alignment
    return (parameterEnd + alignment - 1) & -alignment
  }

  private func loadParameters(
    at offset: Int,
    count: Int,
    isImplicit: Bool
  ) -> [GenericParameterDescriptor] {
    guard isImplicit == false else { return [] }
    return Array(unsafeUninitializedCapacity: count) {
      for index in 0 ..< count {
        $0[index] = (ptr + offset).load(
          fromByteOffset: index * MemoryLayout<GenericParameterDescriptor>.stride,
          as: GenericParameterDescriptor.self
        )
      }
      $1 = count
    }
  }

  private func loadRequirements(
    at offset: Int,
    count: Int
  ) -> [GenericRequirementDescriptor] {
    Array(unsafeUninitializedCapacity: count) {
      for index in 0 ..< count {
        $0[index] = GenericRequirementDescriptor(
          ptr: (ptr + offset).advanced(
            by: index * MemoryLayout<_GenericRequirementDescriptor>.stride
          )
        )
      }
      $1 = count
    }
  }
}

extension ExtendedExistentialTypeShape {
  /// Flags for an extended existential shape.
  public struct Flags {
    /// Flags as represented in bits.
    public let bits: UInt32

    /// The representation selected for values of this existential.
    public var specialKind: SpecialKind? {
      SpecialKind(rawValue: UInt8(truncatingIfNeeded: bits))
    }

    /// Whether the shape has a generalization signature.
    public var hasGeneralizationSignature: Bool { bits & 0x100 != 0 }

    /// Whether the shape carries a mangled type subexpression.
    public var hasTypeExpression: Bool { bits & 0x200 != 0 }

    /// Whether the shape carries suggested value witnesses.
    public var hasSuggestedValueWitnesses: Bool { bits & 0x400 != 0 }

    /// Whether requirement-signature parameters are canonical implicit ones.
    public var hasImplicitRequirementSignatureParameters: Bool { bits & 0x800 != 0 }

    /// Whether generalization-signature parameters are canonical implicit ones.
    public var hasImplicitGeneralizationSignatureParameters: Bool { bits & 0x1000 != 0 }

    /// Whether the generalization signature carries type-pack shape records.
    public var hasTypePacks: Bool { bits & 0x2000 != 0 }
  }

  /// The existential value representation selected by its shape.
  public enum SpecialKind: UInt8 {
    case opaque = 0
    case `class` = 1
    case metatype = 2
    case explicitLayout = 3
  }
}

extension ExtendedExistentialTypeShape: Equatable {}

/// Header shared by a constrained existential's generic signatures.
public struct GenericSignatureHeader {
  /// Number of source generic parameters.
  public let numParams: UInt16

  /// Number of generic requirements.
  public let numRequirements: UInt16

  /// Number of argument-layout words.
  public let numKeyArguments: UInt16

  private let flags: UInt16
}

struct _ExtendedExistentialMetadata {
  let _kind: Int
  let _shape: SignedPointer<_ExtendedExistentialTypeShape>
}

struct _ExtendedExistentialTypeShape {
  let _flags: ExtendedExistentialTypeShape.Flags
  let _existentialType: RelativeDirectPointer<CChar>
  let _requirementSignature: _GenericContextDescriptorHeader
}

/// Metadata for a `Builtin.FixedArray` type.
public struct FixedArrayMetadata: Metadata, LayoutWrapper {
  typealias Layout = _FixedArrayMetadata

  /// Backing fixed-array metadata pointer.
  public let ptr: UnsafeRawPointer

  /// The stored array count. A negative count represents an uninhabited type.
  public var count: Int { layout._count }

  /// The count realizable by an instantiated value.
  public var realizedCount: Int { max(count, 0) }

  /// The element type stored by the fixed array.
  public var elementType: Any.Type { layout._element }

  /// Metadata for `elementType`.
  public var elementMetadata: Metadata { reflect(elementType) }
}

extension FixedArrayMetadata: Equatable {}

struct _FixedArrayMetadata {
  let _kind: Int
  let _count: Int
  let _element: Any.Type
}

/// Metadata for an imported non-Swift, non-Objective-C reference type.
public struct ForeignReferenceTypeMetadata: Metadata, LayoutWrapper {
  typealias Layout = _ForeignReferenceTypeMetadata

  /// Backing foreign-reference metadata pointer.
  public let ptr: UnsafeRawPointer

  /// The foreign type's class descriptor.
  public var descriptor: ClassDescriptor {
    ClassDescriptor(ptr: layout._descriptor.signed)
  }
}

extension ForeignReferenceTypeMetadata: Equatable {}

struct _ForeignReferenceTypeMetadata {
  let _kind: Int
  let _descriptor: SignedPointer<ClassDescriptor>
  let _reserved: UnsafeRawPointer
}
