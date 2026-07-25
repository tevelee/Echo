import Foundation
import Testing
import Echo

struct Cat3<T, U: Equatable> {}

enum GenericContextTests {
  static func testNoRequirements() throws {
    let metadata = reflectStruct(Cat2<Int, String>.self)!
    #expect(metadata.descriptor.flags.isGeneric)
    let gc = metadata.descriptor.genericContext!
    
    #expect(gc.numExtraArguments == 0)
    #expect(gc.numKeyArguments == 2)
    #expect(gc.numParams == 2)
    #expect(gc.numRequirements == 0)
    #expect(gc.size == 12)
    #expect(gc.parameters.map { $0.bits } == [128, 128])
    #expect(gc.requirements.count == 0)
    
    // TYPE
    
    let typeGc = metadata.descriptor.typeGenericContext
    #expect(typeGc.size == 20)
    #expect(typeGc.genericMetadataPattern.flags.bits == 1073741824)
  }
  
  static func testRequirements() throws {
    let metadata = reflectStruct(Cat3<Int, String>.self)!
    #expect(metadata.descriptor.flags.isGeneric)
    let gc = metadata.descriptor.genericContext!
    
    #expect(gc.numExtraArguments == 0)
    #expect(gc.numKeyArguments == 3)
    #expect(gc.numParams == 2)
    #expect(gc.numRequirements == 1)
    #expect(gc.size == 24)
    #expect(gc.parameters.map { $0.bits } == [128, 128])
    #expect(gc.requirements.count == 1)
    
    for (i, requirement) in gc.requirements.enumerated() {
      switch i {
      case 0:
        #expect(requirement.flags.kind == .protocol)
        #expect(requirement.protocol.name == "Equatable")
      default:
        break
      }
    }
    
    // TYPE
    
    let typeGc = metadata.descriptor.typeGenericContext
    #expect(typeGc.size == 32)
    #expect(typeGc.genericMetadataPattern.flags.bits == 1073741824)
  }
}

extension EchoTests {
  @Test
  func testGenericContext() throws {
    try GenericContextTests.testNoRequirements()
    try GenericContextTests.testRequirements()
  }
}
