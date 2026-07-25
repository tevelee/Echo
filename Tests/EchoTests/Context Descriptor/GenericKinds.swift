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
}
