import Foundation
import Testing
import Echo

struct Dog {
  let name: String
  let age: Int
}

extension EchoTests {
  @Test
  func testStructDescriptor() throws {
    let metadata = reflectStruct(Dog.self)!
    let descriptor = metadata.descriptor
    #expect(descriptor.numFields == 2)
    #expect(descriptor.fieldOffsetVectorOffset == 2)
    #expect(descriptor.foreignMetadataInitialization == nil)
    #expect(descriptor.singletonMetadataInitialization == nil)
  }
}

