import Foundation
import Testing
import Echo

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
}
