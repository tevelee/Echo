import Foundation
import Testing
import Echo

extension EchoTests {
  @Test
  func testMetatypeMetadata() throws {
    let metadata = try #require(reflect(Int.Type.self) as? MetatypeMetadata)
    
    #expect(typesEqual(metadata.instanceType, Int.self))
    #expect(metadata.kind == .metatype)
    
    // VWT
    
    var extraInhabitantCount = 2147483647
    #if os(Linux)
    extraInhabitantCount = 4096
    #endif
    
    #expect(metadata.vwt.extraInhabitantCount == extraInhabitantCount)
    #expect(metadata.vwt.size == 8)
    #expect(metadata.vwt.stride == 8)
    #expect(metadata.vwt.flags.bits == 7)
  }
}
