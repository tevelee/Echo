import Foundation
import Testing
import Echo

class Super {
  let name: String
  
  init(name: String) {
    self.name = name
  }
  
  func sayHello() {}
}

class Child: Super {}

extension EchoTests {
  @Test
  func testClassDescriptor() {
    let metadata = reflectClass(Super.self)!
    let descriptor = metadata.descriptor!
    #expect(descriptor.superclass.load(as: CChar.self) == 0) // nullptr
    #expect(descriptor.numFields == 1)
    #expect(descriptor.numMembers == 3) // name, init, sayHello
    #if canImport(ObjectiveC)
    #expect(descriptor.fieldOffsetVectorOffset == 10)
    #else
    #expect(descriptor.fieldOffsetVectorOffset == 7)
    #endif
    
    let child = reflectClass(Child.self)!
    let childDescriptor = child.descriptor!
    let size = getSymbolicMangledNameLength(childDescriptor.superclass)
    // 5 because symbolic prefix (1), symbol (4)
    #expect(size == 5)
    #expect(childDescriptor.numFields == 0)
    #expect(childDescriptor.numMembers == 0)
    #if canImport(ObjectiveC)
    #expect(childDescriptor.fieldOffsetVectorOffset == 13)
    #else
    #expect(childDescriptor.fieldOffsetVectorOffset == 10)
    #endif
  }
}
