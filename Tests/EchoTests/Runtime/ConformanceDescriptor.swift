import Foundation
import Testing
import Echo

protocol Wheel {}
protocol DumbWheel {}

struct CheeseWheel: Wheel {}
extension CheeseWheel: Equatable {}
extension CheeseWheel: DumbWheel {}

extension EchoTests {
  @Test
  func testConformanceDescriptor() throws {
    let metadata = reflectStruct(CheeseWheel.self)!
    let wheelConf = metadata.conformances[0]
    
    #expect(wheelConf.contextDescriptor != nil)
    #if canImport(ObjectiveC)
    #expect(wheelConf.objcClass == nil)
    #endif
    #expect(wheelConf.flags.bits == 0)
    #expect(wheelConf.protocol.name == "Wheel")
  }
}
