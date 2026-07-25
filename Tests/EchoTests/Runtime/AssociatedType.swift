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

private protocol ComparableAssociatedTypeContainer {
  associatedtype Item: Comparable
}

private struct IntComparableAssociatedTypeContainer: ComparableAssociatedTypeContainer {
  typealias Item = Int
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

  @Test
  func associatedConformanceWitnessResolves() throws {
    let metadata = try #require(reflectStruct(IntComparableAssociatedTypeContainer.self))
    let conformance = try #require(metadata.conformances.first {
      $0.protocol.name == "ComparableAssociatedTypeContainer"
    })
    let comparableMetadata = try #require(
      reflect(_typeByName("SL")!) as? ExistentialMetadata
    )
    let comparable = try #require(comparableMetadata.protocols.first)

    let witness = try #require(metadata.associatedConformance(
      ofAssociatedType: "Item",
      to: comparable,
      conformingTo: conformance.protocol
    ))
    let intComparable = try #require(
      swift_conformsToProtocol(type: Int.self, protocol: comparable)
    )

    #expect(witness == intComparable)
  }
}
