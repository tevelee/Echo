import Testing
@testable import Echo

extension EchoTests {
  @Test
  func heapBackedPacksDecodeTheirElementsAndStackPacksRemainOpaque() {
    let wordSize = MemoryLayout<UnsafeRawPointer>.stride
    let storage = UnsafeMutableRawPointer.allocate(byteCount: wordSize * 3, alignment: wordSize)
    defer { storage.deallocate() }

    storage.storeBytes(of: UInt(2), as: UInt.self)
    storage.storeBytes(of: reflect(Int.self).ptr, toByteOffset: wordSize, as: UnsafeRawPointer.self)
    storage.storeBytes(of: reflect(String.self).ptr, toByteOffset: wordSize * 2, as: UnsafeRawPointer.self)

    let elements = UnsafeRawPointer(storage + wordSize)
    let heapPointer = UnsafeRawPointer(bitPattern: UInt(bitPattern: elements) | 1)!
    let metadataPack = MetadataPack(taggedPointer: heapPointer)

    #expect(metadataPack.lifetime == .onHeap)
    #expect(metadataPack.elementsPointer == elements)
    #expect(metadataPack.count == 2)
    #expect(metadataPack.elements.map(\.ptr) == [reflect(Int.self).ptr, reflect(String.self).ptr])

    let stackPack = MetadataPack(taggedPointer: elements)
    #expect(stackPack.lifetime == .onStack)
    #expect(stackPack.count == nil)
    #expect(stackPack.elements.isEmpty)

    let firstWitness = UnsafeRawPointer(storage + wordSize)
    let secondWitness = UnsafeRawPointer(storage + wordSize * 2)
    storage.storeBytes(of: firstWitness, toByteOffset: wordSize, as: UnsafeRawPointer.self)
    storage.storeBytes(of: secondWitness, toByteOffset: wordSize * 2, as: UnsafeRawPointer.self)

    let witnessPack = WitnessTablePack(taggedPointer: heapPointer)
    #expect(witnessPack.lifetime == .onHeap)
    #expect(witnessPack.elementsPointer == elements)
    #expect(witnessPack.count == 2)
    #expect(witnessPack.elements.map(\.ptr) == [firstWitness, secondWitness])

    let stackWitnessPack = WitnessTablePack(taggedPointer: elements)
    #expect(stackWitnessPack.lifetime == .onStack)
    #expect(stackWitnessPack.count == nil)
    #expect(stackWitnessPack.elements.isEmpty)

    #expect(GenericArgument.metadataPack(heapPointer).metadataPackValue?.elementsPointer == elements)
    #expect(GenericArgument.witnessTablePack(heapPointer).witnessTablePackValue?.elementsPointer == elements)
  }
}
