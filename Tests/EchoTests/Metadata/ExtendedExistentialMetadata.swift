import Testing
@testable import Echo

extension EchoTests {
  @Test
  func constrainedExistentialMetadata() throws {
    let metadata = try #require(
      reflect((any Collection<Int>).self) as? ExtendedExistentialMetadata
    )

    #expect(metadata.knownKind == .extendedExistential)
    #expect(metadata.isTypeMetadata)
    #expect(metadata.shape.flags.hasGeneralizationSignature)
    #expect(metadata.shape.generalizationArgumentCount > 0)
    #expect(metadata.shape.requirementParameterCount > 0)
    #expect(metadata.shape.requirementCount > 0)
    #expect(metadata.shape.generalizationSignature != nil)
  }

  @Test
  func extendedExistentialShapeDecodesGeneralizationPackShapes() {
    let storage = UnsafeMutableRawPointer.allocate(byteCount: 64, alignment: 8)
    storage.initializeMemory(as: UInt8.self, repeating: 0, count: 64)
    defer { storage.deallocate() }

    storage.storeBytes(
      of: _ExtendedExistentialTypeShape(
        _flags: ExtendedExistentialTypeShape.Flags(bits: 0x2100),
        _existentialType: RelativeDirectPointer<CChar>(offset: 0),
        _requirementSignature: _GenericContextDescriptorHeader(
          _numParams: 0,
          _numRequirements: 0,
          _numKeyArguments: 0,
          _numExtraArguments: 0
        )
      ),
      as: _ExtendedExistentialTypeShape.self
    )
    storage.storeBytes(
      of: GenericPackShapeHeader(numPacks: 2, numShapeClasses: 1),
      toByteOffset: 24,
      as: GenericPackShapeHeader.self
    )
    storage.storeBytes(of: UInt16(0), toByteOffset: 28, as: UInt16.self)
    storage.storeBytes(of: UInt16(3), toByteOffset: 30, as: UInt16.self)
    storage.storeBytes(of: UInt16(0), toByteOffset: 32, as: UInt16.self)
    storage.storeBytes(of: UInt16(1), toByteOffset: 36, as: UInt16.self)
    storage.storeBytes(of: UInt16(4), toByteOffset: 38, as: UInt16.self)
    storage.storeBytes(of: UInt16(0), toByteOffset: 40, as: UInt16.self)

    let shape = ExtendedExistentialTypeShape(ptr: UnsafeRawPointer(storage))
    #expect(shape.generalizationPackShapeHeader?.numPacks == 2)
    #expect(shape.generalizationPackShapeHeader?.numShapeClasses == 1)
    #expect(shape.generalizationPackShapeDescriptors.count == 2)
    #expect(shape.generalizationPackShapeDescriptors[0].kind == .metadata)
    #expect(shape.generalizationPackShapeDescriptors[0].index == 3)
    #expect(shape.generalizationPackShapeDescriptors[1].kind == .witnessTable)
    #expect(shape.generalizationPackShapeDescriptors[1].index == 4)
  }

  @Test
  func nonUniqueExtendedExistentialShapeExposesItsCacheAndLocalShape() {
    let storage = UnsafeMutableRawPointer.allocate(byteCount: 128, alignment: 8)
    storage.initializeMemory(as: UInt8.self, repeating: 0, count: 128)
    defer { storage.deallocate() }

    let cache = UnsafeRawPointer(storage + 96)
    storage.storeBytes(
      of: _NonUniqueExtendedExistentialTypeShape(
        _uniquenessCache: RelativeDirectPointer<Void>(offset: 96),
        _localShape: _ExtendedExistentialTypeShape(
          _flags: ExtendedExistentialTypeShape.Flags(bits: 0x101),
          _existentialType: RelativeDirectPointer<CChar>(offset: 0),
          _requirementSignature: _GenericContextDescriptorHeader(
            _numParams: 0,
            _numRequirements: 0,
            _numKeyArguments: 0,
            _numExtraArguments: 0
          )
        )
      ),
      as: _NonUniqueExtendedExistentialTypeShape.self
    )

    let shape = NonUniqueExtendedExistentialTypeShape(ptr: UnsafeRawPointer(storage))
    #expect(shape.uniquenessCache == cache)
    #expect(shape.localShape.flags.specialKind == .class)
    #expect(shape.localShape.flags.hasGeneralizationSignature)
  }

  @Test
  func unknownMetadataKindFailsClosed() {
    let storage = UnsafeMutableRawPointer.allocate(
      byteCount: MemoryLayout<Int>.size,
      alignment: MemoryLayout<Int>.alignment
    )
    defer { storage.deallocate() }
    storage.storeBytes(of: 0x277, as: Int.self)

    let metadata = getMetadata(at: UnsafeRawPointer(storage))
    #expect(metadata is UnknownMetadata)
    #expect(metadata.knownKind == nil)
    #expect(metadata.rawKind == 0x277)
    #expect(metadata.isTypeMetadata)
  }
}
