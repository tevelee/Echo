import Testing
@testable import Echo

extension EchoTests {
  @Test
  func keyPathHeadersDecodeModernComputedResolutionStates() {
    let computed = KeyPathComponentHeader(
      bits: (2 << 24) | 0x0040_0000 | 0x0010_0000 | 0x0008_0000 | 0x3
    )
    #expect(computed.kind == .computed)
    #expect(computed.computedPropertyKind == .settableNonmutating)
    #expect(computed.computedIdentifierKind == .vtableOffset)
    #expect(computed.computedIdentifierResolution == .resolvedAbsolute)
    #expect(computed.hasComputedArguments == true)

    let stored = KeyPathComponentHeader(bits: (1 << 24) | 0x0080_0000 | 24)
    #expect(stored.storedOffset == 24)
    #expect(stored.storedOffsetKind == .inline)
    #expect(stored.isStoredPropertyMutable == true)

    let unresolved = KeyPathComponentHeader(bits: (3 << 24) | 0x007F_FFFD)
    #expect(unresolved.storedOffset == nil)
    #expect(unresolved.storedOffsetKind == .unresolvedIndirect)

    let optional = KeyPathComponentHeader(bits: (4 << 24) | 2)
    #expect(optional.optionalOperation == .force)
  }
}
