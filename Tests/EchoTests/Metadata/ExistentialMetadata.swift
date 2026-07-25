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
}
