import Foundation
import Testing
@testable import Echo

extension EchoTests {
  @Test
  func contextDescriptorReservedBitsAreNotACompatibilityVersion() {
    let flags = ContextDescriptorFlags(
      bits: UInt32(ContextDescriptorKind.struct.rawValue) | (UInt32(0xA5) << 8)
    )

    #expect(flags.reservedBits == 0xA5)
  }

  @Test
  func nominalMetadataExposesLayoutStringOnlyWhenAdvertised() {
    let storage = UnsafeMutableRawPointer.allocate(byteCount: 256, alignment: 8)
    defer { storage.deallocate() }
    storage.initializeMemory(as: UInt8.self, repeating: 0, count: 256)

    let descriptor = UnsafeRawPointer(storage)
    let metadata = UnsafeRawPointer(storage + 128)
    let layoutString = UnsafeRawPointer(storage + 200)
    let descriptorFlags = ContextDescriptorFlags(
      bits: UInt32(ContextDescriptorKind.struct.rawValue) | (UInt32(0x10) << 16)
    )
    storage.storeBytes(of: descriptorFlags, as: ContextDescriptorFlags.self)
    storage.storeBytes(of: MetadataKind.struct.rawValue, toByteOffset: 128, as: Int.self)
    storage.storeBytes(of: descriptor, toByteOffset: 136, as: UnsafeRawPointer.self)
    storage.storeBytes(of: layoutString, toByteOffset: 112, as: UnsafeRawPointer.self)

    let reflected = StructMetadata(ptr: metadata)
    #expect(reflected.layoutString == layoutString)

    storage.storeBytes(
      of: ContextDescriptorFlags(bits: UInt32(ContextDescriptorKind.struct.rawValue)),
      as: ContextDescriptorFlags.self
    )
    #expect(reflected.layoutString == nil)
  }
}
