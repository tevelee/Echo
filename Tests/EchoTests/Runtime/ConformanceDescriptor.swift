import Foundation
import Testing
@testable import Echo

protocol Wheel {}
protocol DumbWheel {}

struct CheeseWheel: Wheel {}
extension CheeseWheel: Equatable {}
extension CheeseWheel: DumbWheel {}

private protocol ConditionalConformanceFixture {
  associatedtype Element
  static func equals(_ lhs: Element, _ rhs: Element) -> Bool
}

private struct ConditionalConformance<T> {}

extension ConditionalConformance: ConditionalConformanceFixture where T: Equatable {
  typealias Element = T

  static func equals(_ lhs: T, _ rhs: T) -> Bool {
    lhs == rhs
  }
}

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

  @Test
  func genericConformanceTrailers() throws {
    let metadata = try #require(reflectStruct(ConditionalConformance<Int>.self))
    let conformance = try #require(metadata.conformances.first {
      $0.protocol.name == "ConditionalConformanceFixture"
    })

    #expect(conformance.flags.numConditionalRequirements == 1)
    #expect(conformance.conditionalRequirements.count == 1)
    #expect(conformance.conditionalRequirements.first?.flags.kind == .protocol)
    #expect(conformance.genericWitnessTable?.requiresInstantiation == true)
  }

  @Test
  func conformanceTrailerOrderingIncludesResilientGenericAndActorRecords() {
    let storage = UnsafeMutableRawPointer.allocate(byteCount: 96, alignment: 8)
    storage.initializeMemory(as: UInt8.self, repeating: 0, count: 96)
    defer { storage.deallocate() }

    let flags = ConformanceDescriptor.Flags(
      bits: (1 << 16) | (1 << 17) | (1 << 19) | (2 << 24)
    )
    storage.advanced(by: 12).storeBytes(of: flags, as: ConformanceDescriptor.Flags.self)

    // Two pack descriptors follow the fixed descriptor. The resilient header
    // then has two witnesses, followed by a generic witness table and global
    // actor reference.
    storage.advanced(by: 32).storeBytes(of: UInt32(2), as: UInt32.self)
    storage.advanced(by: 52).storeBytes(of: UInt16(7), as: UInt16.self)
    storage.advanced(by: 54).storeBytes(of: UInt16(5), as: UInt16.self)

    let descriptor = ConformanceDescriptor(ptr: UnsafeRawPointer(storage))
    #expect(descriptor.conditionalPackShapeDescriptors.count == 2)
    #expect(descriptor.resilientWitnesses.count == 2)
    #expect(descriptor.resilientWitnesses.allSatisfy { $0.requirement == nil })
    #expect(descriptor.genericWitnessTable?.sizeInWords == 7)
    #expect(descriptor.genericWitnessTable?.privateSizeInWords == 2)
    #expect(descriptor.genericWitnessTable?.requiresInstantiation == true)
    #expect(descriptor.globalActorReference != nil)
  }
}
