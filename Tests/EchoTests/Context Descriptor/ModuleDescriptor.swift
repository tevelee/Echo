import Foundation
import Testing
import Echo

extension EchoTests {
  @Test
  func testModuleDescriptor() throws {
    let metadata = reflectStruct(Int.self)!
    let module = try #require(metadata.descriptor.parent as? ModuleDescriptor)
    #expect(module.name == "Swift")
    #expect(module.parent == nil)
  }
}
