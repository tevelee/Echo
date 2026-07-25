import Foundation
import Testing
import Echo

private protocol EchoPublicAPICoverageProtocol {
  func value() -> Int
}

private struct EchoPublicAPICoverageConformer: EchoPublicAPICoverageProtocol {
  func value() -> Int { 42 }
}

extension EchoTests {
  @Test
  func testPublicForkAPIs() throws {
    // Keep the conformance reachable in optimized builds.
    #expect(EchoPublicAPICoverageConformer().value() == 42)

    let protocolDescriptor = try #require(Echo.protocols.first { descriptor in
        descriptor.name == "EchoPublicAPICoverageProtocol"
      })
    let conformance = try #require(findConformance(to: protocolDescriptor))
    let namedConformance = try #require(findConformance(toProtocolNamed: "EchoPublicAPICoverageProtocol"))

    #expect(conformance.protocol == protocolDescriptor)
    #expect(namedConformance.protocol == protocolDescriptor)

    let witnessTable = conformance.witnessTablePattern
    let copiedWitnessTable = WitnessTable(ptr: witnessTable.ptr)
    #expect(copiedWitnessTable.ptr == witnessTable.ptr)

    let base = AnyExistentialContainer(type: EchoPublicAPICoverageConformer.self)
    let container = ExistentialContainer(
      base: base,
      witnessTable: copiedWitnessTable
    )
    #expect(typesEqual(container.base.type, EchoPublicAPICoverageConformer.self))
    #expect(container.witnessTable.ptr == copiedWitnessTable.ptr)
  }
}
