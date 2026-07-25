import Foundation
import Testing
@testable import Echo

extension EchoTests {
  @Test
  func importedTypeIdentityDecodesKnownComponentsInABIOrder() throws {
    let storage = UnsafeMutableRawPointer.allocate(byteCount: 128, alignment: 8)
    defer { storage.deallocate() }
    storage.initializeMemory(as: UInt8.self, repeating: 0, count: 128)

    let flags = ContextDescriptorFlags(
      bits: UInt32(ContextDescriptorKind.struct.rawValue) | (UInt32(0x4) << 16)
    )
    storage.storeBytes(of: flags, as: ContextDescriptorFlags.self)
    storage.storeBytes(of: Int32(56), toByteOffset: 8, as: Int32.self)

    let records = Array("DisplayName\0NABIName\0St\0RCode\0\0".utf8)
    for (offset, byte) in records.enumerated() {
      storage.storeBytes(of: byte, toByteOffset: 64 + offset, as: UInt8.self)
    }

    let descriptor = StructDescriptor(ptr: UnsafeRawPointer(storage))
    let importInfo = try #require(descriptor.typeImportInfo)
    #expect(descriptor.name == "DisplayName")
    #expect(descriptor.abiName == "ABIName")
    #expect(importInfo.abiName == "ABIName")
    #expect(importInfo.symbolNamespace == "t")
    #expect(importInfo.relatedEntityName == "Code")
  }

  @Test
  func importedTypeIdentityRejectsUnknownAndOutOfOrderComponents() {
    let storage = UnsafeMutableRawPointer.allocate(byteCount: 128, alignment: 8)
    defer { storage.deallocate() }
    storage.initializeMemory(as: UInt8.self, repeating: 0, count: 128)

    let flags = ContextDescriptorFlags(
      bits: UInt32(ContextDescriptorKind.enum.rawValue) | (UInt32(0x4) << 16)
    )
    storage.storeBytes(of: flags, as: ContextDescriptorFlags.self)
    storage.storeBytes(of: Int32(56), toByteOffset: 8, as: Int32.self)

    let records = Array("Imported\0Xunknown\0\0".utf8)
    for (offset, byte) in records.enumerated() {
      storage.storeBytes(of: byte, toByteOffset: 64 + offset, as: UInt8.self)
    }

    let descriptor = EnumDescriptor(ptr: UnsafeRawPointer(storage))
    #expect(descriptor.typeImportInfo == nil)
    #expect(descriptor.abiName == descriptor.name)

    for offset in 64 ..< 128 {
      storage.storeBytes(of: UInt8(0), toByteOffset: offset, as: UInt8.self)
    }
    let outOfOrder = Array("Imported\0Snamespace\0NABI\0\0".utf8)
    for (offset, byte) in outOfOrder.enumerated() {
      storage.storeBytes(of: byte, toByteOffset: 64 + offset, as: UInt8.self)
    }
    #expect(descriptor.typeImportInfo == nil)
  }
}
