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
