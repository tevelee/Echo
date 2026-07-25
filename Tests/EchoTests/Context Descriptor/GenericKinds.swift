import Foundation
import Testing
@testable import Echo

private struct PlainGeneric<First, Second> {
  var first: First
  var second: Second
}

private struct PackGeneric<each Element> {}

private struct NoncopyableGeneric<Element: ~Copyable> {}

private struct NoncopyableContextFixture: ~Copyable {}

extension EchoTests {
  @Test
  func genericParameterKinds() throws {
    let plain = try #require(reflectStruct(PlainGeneric<Int, String>.self))
    let plainContext = try #require(plain.descriptor.genericContext)
    #expect(plainContext.parameters.count == 2)
    #expect(plainContext.parameters.allSatisfy { $0.kind == .type })

    let pack = try #require(reflectStruct(PackGeneric<Int, String, Bool>.self))
    let packContext = try #require(pack.descriptor.genericContext)
    #expect(packContext.parameters.map(\.kind).contains(.typePack))
    #expect(packContext.descriptorFlags.hasTypePacks)

    let header = try #require(packContext.packShapeHeader)
    #expect(header.numPacks > 0)
    #expect(packContext.packShapeDescriptors.count == Int(header.numPacks))
    #expect(packContext.packShapeDescriptors.contains { $0.kind == .metadata })

    let packArguments = pack.genericArguments
    guard case let .packLength(length) = packArguments.first else {
      Issue.record("Expected a leading pack-length argument.")
      return
    }
    #expect(length == 3)
    guard packArguments.dropFirst().contains(where: {
      if case .metadataPack = $0 { return true }
      return false
    }) else {
      Issue.record("Expected a metadata-pack argument.")
      return
    }
    #expect(pack.genericTypes.isEmpty)

    #expect(plainContext.descriptorFlags.hasTypePacks == false)
    #expect(plainContext.packShapeHeader == nil)
    #expect(plainContext.packShapeDescriptors.isEmpty)

    let noncopyable = try #require(reflectStruct(NoncopyableGeneric<Int>.self))
    let noncopyableContext = try #require(noncopyable.descriptor.genericContext)
    #expect(
      noncopyableContext.requirements.contains {
        $0.flags.kind == .invertedProtocols
      }
    )
    let invertedRequirement = try #require(noncopyableContext.requirements.first {
      $0.flags.kind == .invertedProtocols
    })
    #expect(invertedRequirement.invertedProtocols.invertsCopyable)
    #expect(invertedRequirement.invertedProtocolsGenericParameterIndex == 0)

    let noncopyableType = try #require(reflectStruct(NoncopyableContextFixture.self))
    #expect(noncopyableType.descriptor.flags.hasInvertibleProtocols)
    #expect(noncopyableType.descriptor.invertedProtocols?.invertsCopyable == true)
    #expect(noncopyableType.vwt.flags.isCopyable == false)

    // Copyability and bitwise borrowing are independent ABI properties. A
    // simple noncopyable value can still be bitwise-borrowable, while values
    // that form lifetime dependencies must be passed indirectly.
    let dependencyFlags = ValueWitnessTable.Flags(bits: 0x02000000)
    #expect(dependencyFlags.isAddressableForDependencies)
    #expect(dependencyFlags.isBitwiseBorrowable)
    let nonBorrowableFlags = ValueWitnessTable.Flags(bits: 0x01100000)
    #expect(nonBorrowableFlags.isBitwiseBorrowable == false)

    // Swift 6 emits noncopyable descriptors into the separate types2 image
    // section. Echo must discover that section without handing it to an older
    // runtime as if it contained copyable values.
    #expect(
      Echo.types.contains {
        ($0 as? StructDescriptor)?.name == "NoncopyableContextFixture"
      }
    )
  }

  @Test
  func genericContextConditionalInvertedProtocolsAndValues() throws {
    let buffer = UnsafeMutableRawPointer.allocate(
      byteCount: 64,
      alignment: MemoryLayout<_GenericContextDescriptorHeader>.alignment
    )
    defer { buffer.deallocate() }
    buffer.initializeMemory(as: UInt8.self, repeating: 0, count: 64)

    buffer.storeBytes(
      of: _GenericContextDescriptorHeader(
        _numParams: 0,
        _numRequirements: 0,
        _numKeyArguments: 0,
        _numExtraArguments: 0x6
      ),
      as: _GenericContextDescriptorHeader.self
    )

    // The conditional set contains `Copyable` and `Escapable`. Its two
    // cumulative counts describe one and then three requirements.
    buffer.storeBytes(of: UInt16(0x3), toByteOffset: 8, as: UInt16.self)
    buffer.storeBytes(of: UInt16(1), toByteOffset: 10, as: UInt16.self)
    buffer.storeBytes(of: UInt16(3), toByteOffset: 12, as: UInt16.self)

    // The requirement records are four-byte aligned after the UInt16 records.
    for offset in stride(from: 16, through: 40, by: 12) {
      buffer.storeBytes(of: UInt32(0x5), toByteOffset: offset, as: UInt32.self)
    }

    // Two value-generic descriptors follow the requirements.
    buffer.storeBytes(of: UInt32(2), toByteOffset: 52, as: UInt32.self)
    buffer.storeBytes(of: UInt32(0), toByteOffset: 56, as: UInt32.self)
    buffer.storeBytes(of: UInt32(0), toByteOffset: 60, as: UInt32.self)

    let context = GenericContext(ptr: UnsafeRawPointer(buffer))
    let protocols = try #require(context.conditionalInvertedProtocols)
    #expect(protocols.invertsCopyable)
    #expect(protocols.invertsEscapable)
    #expect(context.conditionalInvertedProtocolRequirementCounts == [1, 3])
    #expect(context.conditionalInvertedProtocolRequirements.count == 3)
    #expect(
      context.conditionalInvertedProtocolRequirements.allSatisfy {
        $0.flags.kind == .invertedProtocols
      }
    )
    #expect(context.genericValueHeader?.numValues == 2)
    #expect(context.genericValueDescriptors.count == 2)
    #expect(context.genericValueDescriptors.allSatisfy { $0.type == .int })
    #expect(context.size == 64)
  }

  @Test
  func genericContextRejectsDecreasingConditionalCounts() {
    let buffer = UnsafeMutableRawPointer.allocate(
      byteCount: 16,
      alignment: MemoryLayout<_GenericContextDescriptorHeader>.alignment
    )
    defer { buffer.deallocate() }
    buffer.initializeMemory(as: UInt8.self, repeating: 0, count: 16)

    buffer.storeBytes(
      of: _GenericContextDescriptorHeader(
        _numParams: 0,
        _numRequirements: 0,
        _numKeyArguments: 0,
        _numExtraArguments: 0x2
      ),
      as: _GenericContextDescriptorHeader.self
    )
    buffer.storeBytes(of: UInt16(0x3), toByteOffset: 8, as: UInt16.self)
    buffer.storeBytes(of: UInt16(2), toByteOffset: 10, as: UInt16.self)
    buffer.storeBytes(of: UInt16(1), toByteOffset: 12, as: UInt16.self)

    let context = GenericContext(ptr: UnsafeRawPointer(buffer))
    #expect(context.conditionalInvertedProtocols == nil)
    #expect(context.conditionalInvertedProtocolRequirementCounts.isEmpty)
    #expect(context.conditionalInvertedProtocolRequirements.isEmpty)
  }

  @Test
  func sameConformanceRequirementsResolveDirectAndIndirectDescriptors() {
    let buffer = UnsafeMutableRawPointer.allocate(
      byteCount: 80,
      alignment: MemoryLayout<UnsafeRawPointer>.alignment
    )
    defer { buffer.deallocate() }
    buffer.initializeMemory(as: UInt8.self, repeating: 0, count: 80)

    // Generic requirement descriptors are 12 bytes. Place their payload
    // field at offsets 8 and 24, then exercise direct and indirect relative
    // pointer encodings against the same conformance descriptor at offset 64.
    buffer.storeBytes(
      of: _GenericRequirementDescriptor(
        _flags: GenericRequirementDescriptor.Flags(bits: 0x3),
        _param: RelativeDirectPointer<CChar>(offset: 0),
        _requirement: 56
      ),
      as: _GenericRequirementDescriptor.self
    )
    buffer.storeBytes(
      of: _GenericRequirementDescriptor(
        _flags: GenericRequirementDescriptor.Flags(bits: 0x3),
        _param: RelativeDirectPointer<CChar>(offset: 0),
        _requirement: 9
      ),
      toByteOffset: 16,
      as: _GenericRequirementDescriptor.self
    )

    let conformanceAddress = UnsafeRawPointer(buffer + 64)
    buffer.storeBytes(of: conformanceAddress, toByteOffset: 32, as: UnsafeRawPointer.self)
    buffer.storeBytes(
      of: _ConformanceDescriptor(
        _protocol: RelativeIndirectablePointer<_ProtocolDescriptor>(offset: 0),
        _typeRef: 0,
        _witnessTablePattern: RelativeDirectPointer<_WitnessTable>(offset: 0),
        _flags: ConformanceDescriptor.Flags(bits: 0)
      ),
      toByteOffset: 64,
      as: _ConformanceDescriptor.self
    )

    let direct = GenericRequirementDescriptor(ptr: UnsafeRawPointer(buffer))
    let indirect = GenericRequirementDescriptor(ptr: UnsafeRawPointer(buffer + 16))
    #expect(direct.conformance.ptr == conformanceAddress)
    #expect(indirect.conformance.ptr == conformanceAddress)
  }

  @Test
  func canonicalMetadataPrespecializationCachingTokensResolve() {
    let storage = UnsafeMutableRawPointer.allocate(byteCount: 128, alignment: 8)
    defer { storage.deallocate() }
    storage.initializeMemory(as: UInt8.self, repeating: 0, count: 128)

    func flags(for kind: ContextDescriptorKind) -> ContextDescriptorFlags {
      ContextDescriptorFlags(
        bits: UInt32(kind.rawValue) | 0x80 | (UInt32(0x8) << 16)
      )
    }

    // A generic struct or enum's 28-byte fixed descriptor is followed by a
    // 16-byte generic header. Its prespecialization count, metadata list, and
    // caching token then begin at offset 44.
    storage.storeBytes(of: flags(for: .struct), as: ContextDescriptorFlags.self)
    storage.storeBytes(of: UInt32(1), toByteOffset: 44, as: UInt32.self)
    storage.storeBytes(of: Int32(60), toByteOffset: 52, as: Int32.self)
    let token = UnsafeRawPointer(storage + 112)
    #expect(
      StructDescriptor(ptr: UnsafeRawPointer(storage))
        .canonicalMetadataPrespecializationCachingOnceToken == token
    )

    storage.storeBytes(of: flags(for: .enum), as: ContextDescriptorFlags.self)
    #expect(
      EnumDescriptor(ptr: UnsafeRawPointer(storage))
        .canonicalMetadataPrespecializationCachingOnceToken == token
    )

    // Classes use the same generic header but have a 44-byte fixed
    // descriptor. Their metadata and accessor lists precede the token.
    storage.initializeMemory(as: UInt8.self, repeating: 0, count: 128)
    storage.storeBytes(of: flags(for: .class), as: ContextDescriptorFlags.self)
    storage.storeBytes(of: UInt32(1), toByteOffset: 60, as: UInt32.self)
    storage.storeBytes(of: Int32(40), toByteOffset: 72, as: Int32.self)
    #expect(
      ClassDescriptor(ptr: UnsafeRawPointer(storage))
        .canonicalMetadataPrespecializationCachingOnceToken == token
    )
  }
}
