import Foundation
import Testing
@testable import Echo

class Super {
  let name: String
  
  init(name: String) {
    self.name = name
  }
  
  func sayHello() {}
}

class Child: Super {}

private class AsyncMethodDescriptorFixture {
  func perform() async {}
}

extension EchoTests {
  @Test
  func testClassDescriptor() {
    let metadata = reflectClass(Super.self)!
    let descriptor = metadata.descriptor!
    #expect(descriptor.superclass.load(as: CChar.self) == 0) // nullptr
    #expect(descriptor.numFields == 1)
    #expect(descriptor.numMembers == 3) // name, init, sayHello
    #if canImport(ObjectiveC)
    #expect(descriptor.fieldOffsetVectorOffset == 10)
    #else
    #expect(descriptor.fieldOffsetVectorOffset == 7)
    #endif
    
    let child = reflectClass(Child.self)!
    let childDescriptor = child.descriptor!
    let size = getSymbolicMangledNameLength(childDescriptor.superclass)
    // 5 because symbolic prefix (1), symbol (4)
    #expect(size == 5)
    #expect(childDescriptor.numFields == 0)
    #expect(childDescriptor.numMembers == 0)
    #if canImport(ObjectiveC)
    #expect(childDescriptor.fieldOffsetVectorOffset == 13)
    #else
    #expect(childDescriptor.fieldOffsetVectorOffset == 10)
    #endif
  }

  @Test
  func asyncMethodDescriptorFlags() throws {
    let metadata = try #require(reflectClass(AsyncMethodDescriptorFixture.self))
    let descriptor = try #require(metadata.descriptor)
    let method = try #require(descriptor.methodDescriptors.first { $0.flags.kind == .method })

    #expect(method.flags.isAsync)
    #expect(method.flags.isCoroutine == false)
    #expect(method.flags.isData)
  }

  @Test
  func classTrailingRecordsPreserveModernOrdering() {
    let storage = UnsafeMutableRawPointer.allocate(byteCount: 128, alignment: 8)
    storage.initializeMemory(as: UInt8.self, repeating: 0, count: 128)
    defer { storage.deallocate() }

    let typeFlags: UInt32 = 0xE040 // default overrides, resilient, overrides, vtable
    let flags = ContextDescriptorFlags(
      bits: UInt32(ContextDescriptorKind.class.rawValue) | 0x20 | (typeFlags << 16)
    )
    storage.storeBytes(of: flags, as: ContextDescriptorFlags.self)
    storage.storeBytes(of: UInt32(1), toByteOffset: 28, as: UInt32.self)

    // The fixed class descriptor is 44 bytes. The following records are a
    // resilient-superclass reference, vtable, override table, Objective-C
    // stub, inverted protocols, aligned following records, and defaults.
    storage.storeBytes(of: UInt32(1), toByteOffset: 52, as: UInt32.self)
    storage.storeBytes(of: UInt32(1), toByteOffset: 64, as: UInt32.self)
    storage.storeBytes(of: Int32(32), toByteOffset: 80, as: Int32.self)
    storage.storeBytes(of: UInt16(1), toByteOffset: 84, as: UInt16.self)
    storage.storeBytes(of: UInt32(1), toByteOffset: 88, as: UInt32.self)

    let descriptor = ClassDescriptor(ptr: UnsafeRawPointer(storage))
    #expect(descriptor.resilientSuperclass == nil)
    #expect(descriptor.extraClassFlags?.hasObjCResilientClassStub == true)
    #expect(descriptor.vtableHeader?.size == 1)
    #expect(descriptor.methodDescriptors.count == 1)
    #expect(descriptor.overrideTableHeader?.numEntries == 1)
    #expect(descriptor.methodOverrideDescriptors.count == 1)
    #expect(descriptor.objcResilientClassStub == UnsafeRawPointer(storage + 112))
    #expect(descriptor.invertedProtocols?.invertsCopyable == true)
    #expect(descriptor.defaultOverrideTableHeader?.numEntries == 1)
    #expect(descriptor.defaultOverrideDescriptors.count == 1)
  }
}
