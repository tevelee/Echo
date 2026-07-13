import XCTest
import Echo

private protocol EchoPublicAPICoverageProtocol {
  func value() -> Int
}

private struct EchoPublicAPICoverageConformer: EchoPublicAPICoverageProtocol {
  func value() -> Int { 42 }
}

extension EchoTests {
  func testPublicForkAPIs() throws {
    // Keep the conformance reachable in optimized builds.
    XCTAssertEqual(EchoPublicAPICoverageConformer().value(), 42)

    let protocolDescriptor = try XCTUnwrap(
      Echo.protocols.first { descriptor in
        descriptor.name == "EchoPublicAPICoverageProtocol"
      }
    )
    let conformance = try XCTUnwrap(findConformance(to: protocolDescriptor))
    let namedConformance = try XCTUnwrap(
      findConformance(toProtocolNamed: "EchoPublicAPICoverageProtocol")
    )

    XCTAssertEqual(conformance.protocol, protocolDescriptor)
    XCTAssertEqual(namedConformance.protocol, protocolDescriptor)

    let witnessTable = conformance.witnessTablePattern
    let copiedWitnessTable = WitnessTable(ptr: witnessTable.ptr)
    XCTAssertEqual(copiedWitnessTable.ptr, witnessTable.ptr)

    let base = AnyExistentialContainer(type: EchoPublicAPICoverageConformer.self)
    let container = ExistentialContainer(
      base: base,
      witnessTable: copiedWitnessTable
    )
    XCTAssertTrue(container.base.type == EchoPublicAPICoverageConformer.self)
    XCTAssertEqual(container.witnessTable.ptr, copiedWitnessTable.ptr)
  }
}
