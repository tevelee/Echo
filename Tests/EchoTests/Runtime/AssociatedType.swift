import Testing
import Echo

private protocol AssociatedTypeContainer {
  associatedtype Item
}

private struct IntAssociatedTypeContainer: AssociatedTypeContainer {
  typealias Item = Int
}

private struct StringAssociatedTypeContainer: AssociatedTypeContainer {
  typealias Item = String
}

extension EchoTests {
  @Test
  func associatedTypeWitnessesResolvePerConformance() throws {
    let metadata = try #require(reflectStruct(IntAssociatedTypeContainer.self))
    let conformance = try #require(metadata.conformances.first {
      $0.protocol.name == "AssociatedTypeContainer"
    })

    #expect(conformance.protocol.associatedTypeNameList == ["Item"])

    let intItem = metadata.associatedType(
      named: "Item",
      conformingTo: conformance.protocol
    )
    #expect(intItem?.type == Int.self)

    let stringItem = try #require(reflectStruct(StringAssociatedTypeContainer.self))
      .associatedType(named: "Item", conformingTo: conformance.protocol)
    #expect(stringItem?.type == String.self)
  }

  @Test
  func unknownAssociatedTypeWitnessIsNil() throws {
    let metadata = try #require(reflectStruct(IntAssociatedTypeContainer.self))
    let conformance = try #require(metadata.conformances.first {
      $0.protocol.name == "AssociatedTypeContainer"
    })

    #expect(metadata.associatedType(
      named: "DoesNotExist",
      conformingTo: conformance.protocol
    ) == nil)
  }
}
