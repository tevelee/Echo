import Echo
import Testing

private struct ProjectedWideValue: Equatable {
  let first: Int
  let second: Int
  let third: Int
}

@Suite
struct ProjectedValueTests {
  @Test
  func exposesTheDynamicTypeAndInitializedStorageWithinTheClosure() {
    let erased: Any = ProjectedWideValue(first: 1, second: 2, third: 3)

    withProjectedValue(of: erased) { type, storage in
      #expect(
        ObjectIdentifier(type) == ObjectIdentifier(ProjectedWideValue.self)
      )
      #expect(
        storage.load(as: ProjectedWideValue.self)
          == ProjectedWideValue(first: 1, second: 2, third: 3)
      )
    }
  }

  @Test
  func keepsMultipleInlineAndBoxedValuesProjectedForOneOperation() {
    let values: [Any] = [
      42,
      ProjectedWideValue(first: 4, second: 5, third: 6),
    ]

    withProjectedValues(of: values) { projections in
      #expect(projections.count == 2)
      #expect(ObjectIdentifier(projections[0].type) == ObjectIdentifier(Int.self))
      #expect(
        ObjectIdentifier(projections[1].type)
          == ObjectIdentifier(ProjectedWideValue.self)
      )
      #expect(projections[0].storage.load(as: Int.self) == 42)
      #expect(
        projections[1].storage.load(as: ProjectedWideValue.self)
          == ProjectedWideValue(first: 4, second: 5, third: 6)
      )
    }
  }
}
