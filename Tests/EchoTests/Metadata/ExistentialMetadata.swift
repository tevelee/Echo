import Foundation
import Testing
import Echo

protocol Testable {}
protocol Testable2 {}

extension EchoTests {
  @Test
  func testExistentialMetadata() throws {
    let metadata = try #require(reflect(Testable.self) as? ExistentialMetadata)
    
    #expect(metadata.flags.bits == 2147483649)
    #expect(metadata.numProtocols == 1)
    #expect(metadata.superclass == nil)
    #expect(metadata.kind == .existential)
    
    // VWT
    
    var extraInhabitantCount = 2147483647
    #if os(Linux)
    extraInhabitantCount = 4096
    #endif
    
    #expect(metadata.vwt.extraInhabitantCount == extraInhabitantCount)
    #expect(metadata.vwt.size == 40)
    #expect(metadata.vwt.stride == 40)
    #expect(metadata.vwt.flags.bits == 196615)

    let swiftReference = try #require(metadata.protocolReferences.first)
    #expect(swiftReference.kind == .swift)
    #expect(swiftReference.swiftProtocol?.name == "Testable")
    #expect(swiftReference.name == "Testable")
    #expect(swiftReference.dispatchStrategy == .swift)
    #expect(swiftReference.needsWitnessTable)
    #expect(swiftReference.hasClassConstraint == false)
    
    // Dual Existential
    
    let metadata2 = try #require(reflect((Testable & Testable2).self) as? ExistentialMetadata)
    
    #expect(metadata2.flags.bits == 2147483650)
    #expect(metadata2.numProtocols == 2)
    #expect(metadata2.superclass == nil)
    #expect(metadata2.kind == .existential)
    
    // VWT
    
    #expect(metadata2.vwt.extraInhabitantCount == extraInhabitantCount)
    #expect(metadata2.vwt.size == 48)
    #expect(metadata2.vwt.stride == 48)
    #expect(metadata2.vwt.flags.bits == 196615)
  }

  #if canImport(ObjectiveC)
  @Test
  func existentialProtocolReferencesDecodeObjectiveCProtocols() throws {
    let metadata = try #require(
      reflect((any NSObjectProtocol).self) as? ExistentialMetadata
    )
    let reference = try #require(metadata.protocolReferences.first)

    #expect(reference.kind == .objc)
    #expect(reference.objcProtocolAddress != nil)
    #expect(reference.name?.isEmpty == false)
    #expect(reference.dispatchStrategy == .objc)
    #expect(reference.needsWitnessTable == false)
    #expect(reference.hasClassConstraint)
    #expect(reference.specialProtocol == nil)
  }
  #endif
}
