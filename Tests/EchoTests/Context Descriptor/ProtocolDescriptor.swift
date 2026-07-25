import Foundation
import Testing
import Echo

protocol ProtocolDescriptorFixture {
  associatedtype Hello
  associatedtype World
  
  var name: String { get set }
  
  func sayHello() -> String
}

extension EchoTests {
  @Test
  func testProtocolDescriptor() throws {
    let metadata = reflect((any ProtocolDescriptorFixture).self) as! ExistentialMetadata
    let proto = metadata.protocols[0]
    
    #expect(proto.associatedTypeNames == "Hello World")
    #expect(proto.name == "ProtocolDescriptorFixture")
    #expect(proto.numRequirements == 6)
    #expect(proto.numRequirementsInSignature == 0)
    #expect(proto.protocolFlags.bits == 1)
    #expect(proto.requirementSignature.count == 0)
    
    for (i, requirement) in proto.requirements.enumerated() {
      switch i {
      case 0:
        #expect(requirement.flags.bits == 7)
      case 1:
        #expect(requirement.flags.bits == 7)
      case 2:
        #expect(requirement.flags.bits == 19)
      case 3:
        #expect(requirement.flags.bits == 20)
      case 4:
        #expect(requirement.flags.bits == 22)
      case 5:
        #expect(requirement.flags.bits == 17)
      default:
        break
      }
    }
  }
}
