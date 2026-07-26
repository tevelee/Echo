import Foundation
import Testing
@testable import Echo

actor FlagActor {
  var counter = 0
}

class FlagPlainClass {
  var x = 0
}

enum FlagThrownError: Error {
  case boom
}

enum MetadataFlagsTests {
  static func testValueWitnessCopyability() {
    let intFlags = reflect(Int.self).vwt.flags
    #expect(intFlags.isCopyable)
    #expect(intFlags.isBitwiseBorrowable)

    #expect(reflect(String.self).vwt.flags.isCopyable)
  }

  static func testFunctionFlags() {
    let plain = reflect((() -> Void).self) as! FunctionMetadata
    #expect(plain.flags.isAsync == false)
    #expect(plain.flags.throws == false)
    #expect(plain.flags.isSendable == false)
    #expect(plain.flags.hasGlobalActor == false)

    #expect((reflect((() async -> Void).self) as! FunctionMetadata).flags.isAsync)
    #expect((reflect((() throws -> Void).self) as! FunctionMetadata).flags.throws)
    #expect((reflect((@Sendable () -> Void).self) as! FunctionMetadata).flags.isSendable)

    let asyncThrows = reflect((() async throws -> Void).self) as! FunctionMetadata
    #expect(asyncThrows.flags.isAsync)
    #expect(asyncThrows.flags.throws)

    #expect((reflect((@MainActor () -> Void).self) as! FunctionMetadata).flags.hasGlobalActor)
  }

  static func testActorFlags() {
    let actorMetadata = reflectClass(FlagActor.self)!
    #expect(actorMetadata.isActor)
    #expect(actorMetadata.isDefaultActor)

    let plainMetadata = reflectClass(FlagPlainClass.self)!
    #expect(plainMetadata.isActor == false)
    #expect(plainMetadata.isDefaultActor == false)

    #if canImport(ObjectiveC)
    let nsObject = reflectClass(NSObject.self)!
    #expect(nsObject.isActor == false)
    #expect(nsObject.isDefaultActor == false)
    #endif
  }
}

extension EchoTests {
  @Test
  func testMetadataFlags() {
    MetadataFlagsTests.testValueWitnessCopyability()
    MetadataFlagsTests.testFunctionFlags()
    MetadataFlagsTests.testActorFlags()

    let extendedFunctionFlags = FunctionMetadata.Flags(
      bits: Int(truncatingIfNeeded: UInt32(1) << 31)
    )
    #expect(extendedFunctionFlags.hasExtendedFlags)

    if Int.bitWidth > 32 {
      let upperWordFlag = FunctionMetadata.Flags(
        bits: Int(truncatingIfNeeded: UInt64(1) << 32)
      )
      #expect(upperWordFlag.hasExtendedFlags == false)
    }

    let staticSpecialization = ClassMetadata.Flags(bits: 0x8)
    #expect(staticSpecialization.isStaticSpecialization)
    #expect(staticSpecialization.isCanonicalStaticSpecialization == false)

    let canonicalSpecialization = ClassMetadata.Flags(bits: 0x18)
    #expect(canonicalSpecialization.isStaticSpecialization)
    #expect(canonicalSpecialization.isCanonicalStaticSpecialization)
  }

  @Test
  func functionTrailingMetadata() throws {
    let plain = try #require(reflect((() -> Void).self) as? FunctionMetadata)
    #expect(plain.globalActorType == nil)
    #expect(plain.extendedFlags == nil)
    #expect(plain.thrownErrorType == nil)

    let mainActorFunction = try #require(
      reflect((@MainActor () -> Void).self) as? FunctionMetadata
    )
    #expect(mainActorFunction.flags.hasGlobalActor)
    #expect(typesEqual(mainActorFunction.globalActorType, MainActor.self))

    if #available(macOS 15, iOS 18, tvOS 18, watchOS 11, *) {
      let typedThrows = try #require(
        reflect((() throws(FlagThrownError) -> Void).self) as? FunctionMetadata
      )
      #expect(typedThrows.flags.hasExtendedFlags)

      let extended = try #require(typedThrows.extendedFlags)
      #expect(extended.isTypedThrows)
      #expect(extended.invertedProtocols.isEmpty)
      #expect(extended.invertedProtocols.invertsCopyable == false)
      #expect(extended.invertedProtocols.invertsEscapable == false)
      #expect(typesEqual(typedThrows.thrownErrorType, FlagThrownError.self))
    }
  }

  @Test
  func staticSpecializationTrailingFlagsFollowStructAndEnumLayouts() {
    let storage = UnsafeMutableRawPointer.allocate(byteCount: 256, alignment: 8)
    defer { storage.deallocate() }
    storage.initializeMemory(as: UInt8.self, repeating: 0, count: 256)

    let descriptor = UnsafeRawPointer(storage)
    let metadata = UnsafeRawPointer(storage + 128)

    // A 28-byte value descriptor is followed by the 16-byte type-generic
    // context header. Its pattern pointer is relative to byte 32.
    storage.storeBytes(
      of: ContextDescriptorFlags(
        bits: UInt32(ContextDescriptorKind.struct.rawValue) | 0x80
      ),
      as: ContextDescriptorFlags.self
    )
    storage.storeBytes(of: UInt32(2), toByteOffset: 20, as: UInt32.self)
    storage.storeBytes(of: UInt32(3), toByteOffset: 24, as: UInt32.self)
    storage.storeBytes(of: Int32(32), toByteOffset: 32, as: Int32.self)
    storage.storeBytes(of: UInt16(1), toByteOffset: 40, as: UInt16.self)
    storage.storeBytes(of: UInt32(0x2), toByteOffset: 72, as: UInt32.self)

    storage.storeBytes(of: MetadataKind.struct.rawValue, toByteOffset: 128, as: Int.self)
    storage.storeBytes(of: descriptor, toByteOffset: 136, as: UnsafeRawPointer.self)
    // The two field offsets occupy a full word at offset 3. The flags follow
    // at offset 4.
    storage.storeBytes(of: UInt64(0x3), toByteOffset: 160, as: UInt64.self)

    let reflectedStruct = StructMetadata(ptr: metadata)
    #expect(reflectedStruct.trailingFlags?.bits == 0x3)
    #expect(reflectedStruct.isStaticallySpecializedGenericMetadata)
    #expect(reflectedStruct.isCanonicalStaticallySpecializedGenericMetadata)

    storage.initializeMemory(as: UInt8.self, repeating: 0, count: 256)
    storage.storeBytes(
      of: ContextDescriptorFlags(
        bits: UInt32(ContextDescriptorKind.enum.rawValue) | 0x80
      ),
      as: ContextDescriptorFlags.self
    )
    storage.storeBytes(of: Int32(32), toByteOffset: 32, as: Int32.self)
    storage.storeBytes(of: UInt16(1), toByteOffset: 40, as: UInt16.self)
    storage.storeBytes(of: UInt32(0x2), toByteOffset: 72, as: UInt32.self)
    storage.storeBytes(of: MetadataKind.enum.rawValue, toByteOffset: 128, as: Int.self)
    storage.storeBytes(of: descriptor, toByteOffset: 136, as: UnsafeRawPointer.self)
    // Enum metadata starts its generic arguments at word 2, so one argument
    // places the trailing flags at word 3.
    storage.storeBytes(of: UInt64(0x1), toByteOffset: 152, as: UInt64.self)

    let reflectedEnum = EnumMetadata(ptr: metadata)
    #expect(reflectedEnum.trailingFlags?.bits == 0x1)
    #expect(reflectedEnum.isStaticallySpecializedGenericMetadata)
    #expect(reflectedEnum.isCanonicalStaticallySpecializedGenericMetadata == false)

    storage.storeBytes(of: UInt32(0), toByteOffset: 72, as: UInt32.self)
    #expect(reflectedEnum.trailingFlags == nil)
  }

  @Test
  func singletonAndResilientClassInitializationRecordsResolvePointers() {
    let storage = UnsafeMutableRawPointer.allocate(byteCount: 320, alignment: 8)
    defer { storage.deallocate() }
    storage.initializeMemory(as: UInt8.self, repeating: 0, count: 320)

    storage.storeBytes(
      of: _SingletonMetadataInitialization(
        _initializationCache: RelativeDirectPointer<Void>(offset: 64),
        _incompleteMetadataOrResilientPattern: 76,
        _completionFunc: RelativeDirectPointer<UnsafeRawPointer>(offset: 88)
      ),
      as: _SingletonMetadataInitialization.self
    )
    let singleton = SingletonMetadataInitialization(ptr: UnsafeRawPointer(storage))
    #expect(singleton.initializationCache == UnsafeRawPointer(storage).advanced(by: 64))
    #expect(
      singleton.initialMetadataOrResilientPattern
        == UnsafeRawPointer(storage).advanced(by: 80)
    )
    #expect(singleton.completionFunction == UnsafeRawPointer(storage).advanced(by: 96))

    storage.storeBytes(
      of: _ForeignMetadataInitialization(
        _completionFunc: RelativeDirectPointer<UnsafeRawPointer>(offset: 96)
      ),
      toByteOffset: 16,
      as: _ForeignMetadataInitialization.self
    )
    let foreign = ForeignMetadataInitialization(ptr: UnsafeRawPointer(storage + 16))
    #expect(foreign.completionFunction == UnsafeRawPointer(storage).advanced(by: 112))

    storage.storeBytes(
      of: _ResilientClassMetadataPattern(
        _relocationFunction: RelativeDirectPointer<UnsafeRawPointer>(offset: 80),
        _destroy: RelativeDirectPointer<UnsafeRawPointer>(offset: 84),
        _ivarDestroyer: RelativeDirectPointer<UnsafeRawPointer>(offset: 88),
        _flags: ClassMetadata.Flags(bits: 0x18),
        _data: RelativeDirectPointer<Void>(offset: 88),
        _metaclass: RelativeDirectPointer<Void>(offset: 92)
      ),
      toByteOffset: 128,
      as: _ResilientClassMetadataPattern.self
    )
    let resilient = ResilientClassMetadataPattern(ptr: UnsafeRawPointer(storage + 128))
    #expect(resilient.relocationFunction == UnsafeRawPointer(storage).advanced(by: 208))
    #expect(resilient.destroyFunction == UnsafeRawPointer(storage).advanced(by: 216))
    #expect(resilient.ivarDestroyer == UnsafeRawPointer(storage).advanced(by: 224))
    #expect(resilient.flags.isStaticSpecialization)
    #expect(resilient.flags.isCanonicalStaticSpecialization)
    #expect(resilient.data == UnsafeRawPointer(storage).advanced(by: 232))
    #expect(resilient.metaclass == UnsafeRawPointer(storage).advanced(by: 240))
  }
}
