import Testing
@testable import Echo

extension EchoTests {
  @Test
  func coroutineAllocatorRecordsDecodeModernStrategiesAndEntryPoints() {
    let storage = UnsafeMutableRawPointer.allocate(byteCount: 128, alignment: 8)
    storage.initializeMemory(as: UInt8.self, repeating: 0, count: 128)
    defer { storage.deallocate() }

    storage.storeBytes(
      of: _CoroutineAllocator(
        _flags: CoroutineAllocatorFlags(bits: 2 | (1 << 8)),
        _allocate: UnsafeRawPointer(storage + 64),
        _deallocate: UnsafeRawPointer(storage + 72),
        _allocateFrame: UnsafeRawPointer(storage + 80),
        _deallocateFrame: UnsafeRawPointer(storage + 88)
      ),
      as: _CoroutineAllocator.self
    )

    let allocator = CoroutineAllocator(ptr: UnsafeRawPointer(storage))
    #expect(allocator.flags.kind == .malloc)
    #expect(allocator.flags.shouldDeallocateImmediately)
    #expect(allocator.allocateFunction == UnsafeRawPointer(storage + 64))
    #expect(allocator.deallocateFunction == UnsafeRawPointer(storage + 72))
    #expect(allocator.allocateFrameFunction == UnsafeRawPointer(storage + 80))
    #expect(allocator.deallocateFrameFunction == UnsafeRawPointer(storage + 88))
    #expect(CoroutineAllocatorFlags(bits: 4).kind == nil)
  }
}
