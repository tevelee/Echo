import Foundation
import Testing
@testable import Echo

protocol ProtocolDescriptorFixture {
  associatedtype Hello
  associatedtype World
  
  var name: String { get set }
  
  func sayHello() -> String
}

private protocol AsyncProtocolDescriptorFixture {
  func perform() async
}

private protocol ClassProtocolDescriptorFixture: AnyObject {}

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
    #expect(proto.protocolFlags.hasClassConstraint == false)
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

  @Test
  func protocolDescriptorModernFlags() throws {
    let error = try #require(reflect((any Error).self) as? ExistentialMetadata)
    let errorDescriptor = try #require(error.protocols.first)
    #expect(errorDescriptor.protocolFlags.specialProtocol == .error)

    let classBound = try #require(
      reflect((any ClassProtocolDescriptorFixture).self) as? ExistentialMetadata
    )
    let classBoundDescriptor = try #require(classBound.protocols.first)
    #expect(classBoundDescriptor.protocolFlags.hasClassConstraint)

    let async = try #require(
      reflect((any AsyncProtocolDescriptorFixture).self) as? ExistentialMetadata
    )
    let asyncRequirement = try #require(async.protocols.first?.requirements.first)
    #expect(asyncRequirement.flags.kind == .method)
    #expect(asyncRequirement.flags.isAsync)
    #expect(asyncRequirement.flags.isCoroutine == false)
    #expect(asyncRequirement.flags.isData)
    #expect(asyncRequirement.flags.isSignedWithAddress)
    #expect(asyncRequirement.flags.isFunctionImplementation == false)
  }

  @Test
  func protocolRequirementResolvesDefaultImplementation() {
    let storage = UnsafeMutableRawPointer.allocate(
      byteCount: 64,
      alignment: MemoryLayout<_ProtocolRequirement>.alignment
    )
    defer { storage.deallocate() }
    storage.initializeMemory(as: UInt8.self, repeating: 0, count: 64)

    storage.storeBytes(
      of: _ProtocolRequirement(
        _flags: ProtocolRequirement.Flags(bits: 0x1),
        _defaultImpl: RelativeDirectPointer<()>(offset: 28)
      ),
      as: _ProtocolRequirement.self
    )

    let requirement = ProtocolRequirement(ptr: UnsafeRawPointer(storage))
    #expect(requirement.defaultImplementation == UnsafeRawPointer(storage).advanced(by: 32))

    storage.storeBytes(of: Int32(0), toByteOffset: 4, as: Int32.self)
    #expect(requirement.defaultImplementation == nil)
  }
}
