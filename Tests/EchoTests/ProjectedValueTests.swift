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
}
