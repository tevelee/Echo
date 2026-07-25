import Foundation
import Testing
import Echo

extension EchoTests {
  @Test
  func testOpaqueMetadata() throws {
    let int128 = Echo.KnownMetadata.Builtin.int128
    let int512 = Echo.KnownMetadata.Builtin.int512
    #expect((int128 == int512) == false)
    #expect(int128.kind == .opaque)
    
    // VWT
    
    #expect(int512.vwt.extraInhabitantCount == 0)
    #expect(int512.vwt.size == 64)
    #expect(int512.vwt.stride == 64)
    #expect(int512.vwt.flags.bits == 131087)
  }
}
