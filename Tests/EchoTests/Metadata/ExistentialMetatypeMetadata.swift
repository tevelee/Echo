import Foundation
import Testing
import Echo

extension EchoTests {
  @Test
  func testExistentialMetatypeMetadata() throws {
    let metadata = try #require(reflect(Testable.Type.self) as? ExistentialMetatypeMetadata)
    
    #expect(typesEqual(metadata.instanceType, Testable.self))
    #expect(metadata.flags.bits == 2147483649)
    
    // VWT
    
    var extraInhabitantCount = 2147483647
    #if os(Linux)
    extraInhabitantCount = 4096
    #endif
    
    #expect(metadata.vwt.extraInhabitantCount == extraInhabitantCount)
    #expect(metadata.vwt.size == 16)
    #expect(metadata.vwt.stride == 16)
    #expect(metadata.vwt.flags.bits == 7)
  }
}
