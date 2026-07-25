//
//  ConformanceDescriptor.swift
//  Echo
//
//  Created by Alejandro Alonso
//  Copyright © 2020 - 2021 Alejandro Alonso. All rights reserved.
//

#if canImport(ObjectiveC)
import ObjectiveC
#endif

/// A structure that helps describe a particular conformance in Swift.
/// Information includes what type is being conformed to what protocol, some
/// flags like if the conformance is retroactive, has conditional requirements,
/// etc.
///
/// ABI Stability: Stable since the following
///
///     | macOS | iOS/tvOS | watchOS | Linux | Windows |
///     |-------|----------|---------|-------|---------|
///     | 10.14 | 12.2     | 5.2     | NA    | NA      |
///
public struct ConformanceDescriptor: LayoutWrapper {
  typealias Layout = _ConformanceDescriptor
  
  let ptr: UnsafeRawPointer
  
  /// The specific flags that describe this conformance descriptor.
  public var flags: Flags {
    layout._flags
  }
  
  /// The protocol that this type conforms to.
  public var `protocol`: ProtocolDescriptor {
    ProtocolDescriptor(ptr: address(for: \._protocol))
  }
  
  /// The context descriptor of the type being conformed.
  public var contextDescriptor: TypeContextDescriptor? {
    let start = address(for: \._typeRef)
    let ptr: UnsafeRawPointer?
    
    switch flags.typeReferenceKind {
    case .directTypeDescriptor:
      ptr = start.relativeDirectAddress(as: _ContextDescriptor.self)
    case .indirectTypeDescriptor:
      ptr = start.relativeDirectAddress(as: UnsafeRawPointer?.self).load(as: UnsafeRawPointer?.self)
    default:
      return nil
    }
    
    if let ptr {
      return getContextDescriptor(at: ptr) as? TypeContextDescriptor
    }

    return nil
  }
  
  /// The ObjectiveC class metadata of the type being conformed.
  #if canImport(ObjectiveC)
  public var objcClass: ObjCClassWrapperMetadata? {
    let start = address(for: \._typeRef)
    
    switch flags.typeReferenceKind {
    case .directObjCClass:
      let ptr = start.relativeDirectAddress(as: CChar.self)
        .assumingMemoryBound(to: CChar.self)
      
      guard let anyClass = objc_lookUpClass(ptr) else {
        // A conformance with a nil class means the class was weak-linked
        // from a newer SDK and isn't available in this version of iOS 
        return nil
      }
      
      return reflect(anyClass) as? ObjCClassWrapperMetadata
    case .indirectObjCClass:
      let ptr = start.relativeDirectAddress(as: _ClassMetadata.self)
      return ObjCClassWrapperMetadata(ptr: ptr)
    default:
      return nil
    }
  }
  #endif
  
  /// The witness table pattern is a base witness table that this conformance
  /// can base actual witness tables off of. In the case that this conformance
  /// does not have a generic witness table (flags.hasGenericWitnessTable), this
  /// witness table pattern is actually the real witness table.
  public var witnessTablePattern: WitnessTable {
    WitnessTable(ptr: address(for: \._witnessTablePattern))
  }

  /// The context that owns a retroactive conformance, if recorded.
  public var retroactiveContext: ContextDescriptor? {
    guard let offset = trailingLayout.retroactiveContext else { return nil }
    let field = trailing + offset
    let reference = field.load(as: RelativeIndirectablePointer<_ContextDescriptor>.self)
    guard reference.isNull == false else { return nil }
    return getContextDescriptor(at: reference.address(from: field))
  }

  /// Generic requirements that must hold for this conformance to apply.
  public var conditionalRequirements: [GenericRequirementDescriptor] {
    guard let offset = trailingLayout.conditionalRequirements else { return [] }
    return Array(unsafeUninitializedCapacity: flags.numConditionalRequirements) {
      for index in 0 ..< flags.numConditionalRequirements {
        $0[index] = GenericRequirementDescriptor(
          ptr: (trailing + offset).advanced(
            by: index * MemoryLayout<_GenericRequirementDescriptor>.stride
          )
        )
      }
      $1 = flags.numConditionalRequirements
    }
  }

  /// Pack-shape descriptors used by conditional generic requirements.
  public var conditionalPackShapeDescriptors: [GenericPackShapeDescriptor] {
    guard let offset = trailingLayout.conditionalPackShapeDescriptors else {
      return []
    }
    return Array(unsafeUninitializedCapacity: flags.numConditionalPackShapeDescriptors) {
      for index in 0 ..< flags.numConditionalPackShapeDescriptors {
        $0[index] = (trailing + offset).load(
          fromByteOffset: index * MemoryLayout<GenericPackShapeDescriptor>.stride,
          as: GenericPackShapeDescriptor.self
        )
      }
      $1 = flags.numConditionalPackShapeDescriptors
    }
  }

  /// Witnesses recorded in a resilient conformance pattern.
  public var resilientWitnesses: [ResilientWitness] {
    guard let offset = trailingLayout.resilientWitnesses else { return [] }
    return Array(unsafeUninitializedCapacity: trailingLayout.numResilientWitnesses) {
      for index in 0 ..< trailingLayout.numResilientWitnesses {
        $0[index] = ResilientWitness(
          ptr: (trailing + offset).advanced(
            by: index * MemoryLayout<_ResilientWitness>.stride
          )
        )
      }
      $1 = trailingLayout.numResilientWitnesses
    }
  }

  /// Instantiation metadata for a generic or resilient witness table.
  public var genericWitnessTable: GenericWitnessTable? {
    guard let offset = trailingLayout.genericWitnessTable else { return nil }
    return GenericWitnessTable(ptr: trailing + offset)
  }

  /// Global-actor isolation metadata for this conformance.
  public var globalActorReference: GlobalActorReference? {
    guard let offset = trailingLayout.globalActorReference else { return nil }
    return GlobalActorReference(ptr: trailing + offset)
  }

  private var trailingLayout: TrailingLayout {
    var cursor = 0
    var retroactiveContext: Int?
    var conditionalRequirements: Int?
    var conditionalPackShapeDescriptors: Int?
    var resilientWitnesses: Int?
    var numResilientWitnesses = 0
    var genericWitnessTable: Int?
    var globalActorReference: Int?

    if flags.isRetroactive {
      retroactiveContext = cursor
      cursor += MemoryLayout<RelativeIndirectablePointer<_ContextDescriptor>>.stride
    }

    if flags.numConditionalRequirements > 0 {
      conditionalRequirements = cursor
      cursor += flags.numConditionalRequirements
        * MemoryLayout<_GenericRequirementDescriptor>.stride
    }

    if flags.numConditionalPackShapeDescriptors > 0 {
      conditionalPackShapeDescriptors = cursor
      cursor += flags.numConditionalPackShapeDescriptors
        * MemoryLayout<GenericPackShapeDescriptor>.stride
    }

    if flags.hasResilientWitnesses {
      let header = trailing + cursor
      numResilientWitnesses = Int(header.load(as: _ResilientWitnessesHeader.self).numWitnesses)
      cursor += MemoryLayout<_ResilientWitnessesHeader>.stride
      resilientWitnesses = cursor
      cursor += numResilientWitnesses * MemoryLayout<_ResilientWitness>.stride
    }

    if flags.hasGenericWitnessTable {
      genericWitnessTable = cursor
      cursor += MemoryLayout<_GenericWitnessTable>.stride
    }

    if flags.hasGlobalActorIsolation {
      globalActorReference = cursor
    }

    return TrailingLayout(
      retroactiveContext: retroactiveContext,
      conditionalRequirements: conditionalRequirements,
      conditionalPackShapeDescriptors: conditionalPackShapeDescriptors,
      resilientWitnesses: resilientWitnesses,
      numResilientWitnesses: numResilientWitnesses,
      genericWitnessTable: genericWitnessTable,
      globalActorReference: globalActorReference
    )
  }

  private struct TrailingLayout {
    let retroactiveContext: Int?
    let conditionalRequirements: Int?
    let conditionalPackShapeDescriptors: Int?
    let resilientWitnesses: Int?
    let numResilientWitnesses: Int
    let genericWitnessTable: Int?
    let globalActorReference: Int?
  }
}

/// A requirement and implementation pair in a resilient witness pattern.
public struct ResilientWitness: LayoutWrapper {
  typealias Layout = _ResilientWitness

  let ptr: UnsafeRawPointer

  /// The requirement implemented by this witness, if the entry is non-null.
  public var requirement: ProtocolRequirement? {
    let field = address(for: \._requirement)
    let reference = layout._requirement
    guard reference.isNull == false else { return nil }
    return ProtocolRequirement(ptr: reference.address(from: field))
  }

  /// The opaque implementation pointer. It must not be invoked directly.
  public var implementation: UnsafeRawPointer? {
    let field = address(for: \._implementation)
    guard layout._implementation.isNull == false else { return nil }
    return layout._implementation.address(from: field)
  }
}

/// Instantiation layout information for a generic witness table.
public struct GenericWitnessTable: LayoutWrapper {
  typealias Layout = _GenericWitnessTable

  let ptr: UnsafeRawPointer

  /// The size of the instantiated witness table in machine words.
  public var sizeInWords: Int {
    Int(layout._sizeInWords)
  }

  /// The amount of private storage before the witness-table address point.
  public var privateSizeInWords: Int {
    Int(layout._privateSizeAndRequiresInstantiation >> 1)
  }

  /// Whether the runtime must invoke the instantiator for this table.
  public var requiresInstantiation: Bool {
    layout._privateSizeAndRequiresInstantiation & 0x1 != 0
  }

  /// The opaque instantiation function pointer, if present.
  public var instantiator: UnsafeRawPointer? {
    let field = address(for: \._instantiator)
    guard layout._instantiator.isNull == false else { return nil }
    return layout._instantiator.address(from: field)
  }

  /// Private instantiation data, if the compiler emitted it.
  public var privateData: UnsafeRawPointer? {
    let field = address(for: \._privateData)
    guard layout._privateData.isNull == false else { return nil }
    return layout._privateData.address(from: field)
  }
}

/// The type and conformance used to isolate a conformance to a global actor.
public struct GlobalActorReference: LayoutWrapper {
  typealias Layout = _GlobalActorReference

  let ptr: UnsafeRawPointer

  /// The global actor's symbolic mangled type name.
  public var typeMangledName: UnsafeRawPointer {
    address(for: \._type)
  }

  /// Resolves the global actor's type identity.
  public var type: Any.Type? {
    let name = typeMangledName
    return _getTypeByMangledNameInContext(
      name.assumingMemoryBound(to: UInt8.self),
      UInt(getSymbolicMangledNameLength(name)),
      genericContext: nil,
      genericArguments: nil
    )
  }

  /// The global actor's conformance to `GlobalActor`.
  public var conformance: ConformanceDescriptor? {
    let field = address(for: \._conformance)
    let reference = layout._conformance
    guard reference.isNull == false else { return nil }
    return ConformanceDescriptor(ptr: reference.address(from: field))
  }
}

struct _ConformanceDescriptor {
  let _protocol: RelativeIndirectablePointer<_ProtocolDescriptor>
  let _typeRef: Int32
  let _witnessTablePattern: RelativeDirectPointer<_WitnessTable>
  let _flags: ConformanceDescriptor.Flags
}

struct _ResilientWitnessesHeader {
  let numWitnesses: UInt32
}

struct _ResilientWitness {
  let _requirement: RelativeIndirectablePointer<_ProtocolRequirement>
  let _implementation: RelativeDirectPointer<Void>
}

struct _GenericWitnessTable {
  let _sizeInWords: UInt16
  let _privateSizeAndRequiresInstantiation: UInt16
  let _instantiator: RelativeDirectPointer<Void>
  let _privateData: RelativeDirectPointer<Void>
}

struct _GlobalActorReference {
  let _type: RelativeDirectPointer<CChar>
  let _conformance: RelativeIndirectablePointer<_ConformanceDescriptor>
}
