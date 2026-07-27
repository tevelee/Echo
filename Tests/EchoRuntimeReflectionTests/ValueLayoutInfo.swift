import EchoRuntimeReflection
import Testing

private struct EmptyLayoutFixture {}

private struct PairLayoutFixture {
  let first: Int
  let second: Int
}

@Suite
struct ValueLayoutInfoTests {
  @Test
  func reflectsConcreteLayoutWithoutRawMetadata() {
    let info = ValueLayoutInfo(reflecting: PairLayoutFixture.self)

    #expect(
      ObjectIdentifier(info.type) == ObjectIdentifier(PairLayoutFixture.self)
    )
    #expect(info.size == MemoryLayout<PairLayoutFixture>.size)
    #expect(info.stride == MemoryLayout<PairLayoutFixture>.stride)
    #expect(info.alignment == MemoryLayout<PairLayoutFixture>.alignment)
    #expect(info.isCopyable)
    #expect(info.isBitwiseTakable)
  }

  @Test
  func reflectsZeroSizedLayoutWithoutRawMetadata() {
    let info = ValueLayoutInfo(reflecting: EmptyLayoutFixture.self)

    #expect(info.size == 0)
    #expect(info.stride == 1)
    #expect(info.isValueInline)
    #expect(info.isCopyable)
  }
}
