import Foundation
import Testing
import Echo

private struct PlainGeneric<First, Second> {
  var first: First
  var second: Second
}

private struct PackGeneric<each Element> {}

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

    #expect(plainContext.descriptorFlags.hasTypePacks == false)
    #expect(plainContext.packShapeHeader == nil)
    #expect(plainContext.packShapeDescriptors.isEmpty)
  }
}
