import XCTest
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
  func testClassDescriptor() {
    let metadata = reflectClass(Super.self)!
    let descriptor = metadata.descriptor!
    XCTAssertEqual(descriptor.superclass.load(as: CChar.self), 0) // nullptr
    XCTAssertEqual(descriptor.numFields, 1)
    XCTAssertEqual(descriptor.numMembers, 3) // name, init, sayHello
    #if canImport(ObjectiveC)
    XCTAssertEqual(descriptor.fieldOffsetVectorOffset, 10)
    #else
    XCTAssertEqual(descriptor.fieldOffsetVectorOffset, 7)
    #endif
    
    let child = reflectClass(Child.self)!
    let childDescriptor = child.descriptor!
    let size = getSymbolicMangledNameLength(childDescriptor.superclass)
    // 5 because symbolic prefix (1), symbol (4)
    XCTAssertEqual(size, 5)
    XCTAssertEqual(childDescriptor.numFields, 0)
    XCTAssertEqual(childDescriptor.numMembers, 0)
    #if canImport(ObjectiveC)
    XCTAssertEqual(childDescriptor.fieldOffsetVectorOffset, 13)
    #else
    XCTAssertEqual(childDescriptor.fieldOffsetVectorOffset, 10)
    #endif
  }
}
