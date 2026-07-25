import XCTest
import Echo

actor FlagActor {
  var counter = 0
}

class FlagPlainClass {
  var x = 0
}

enum MetadataFlagsTests {
  static func testValueWitnessCopyability() {
    let intFlags = reflect(Int.self).vwt.flags
    XCTAssertTrue(intFlags.isCopyable)
    XCTAssertTrue(intFlags.isBitwiseBorrowable)

    XCTAssertTrue(reflect(String.self).vwt.flags.isCopyable)
  }

  static func testFunctionFlags() {
    let plain = reflect((() -> Void).self) as! FunctionMetadata
    XCTAssertFalse(plain.flags.isAsync)
    XCTAssertFalse(plain.flags.throws)
    XCTAssertFalse(plain.flags.isSendable)
    XCTAssertFalse(plain.flags.hasGlobalActor)

    XCTAssertTrue((reflect((() async -> Void).self) as! FunctionMetadata).flags.isAsync)
    XCTAssertTrue((reflect((() throws -> Void).self) as! FunctionMetadata).flags.throws)
    XCTAssertTrue((reflect((@Sendable () -> Void).self) as! FunctionMetadata).flags.isSendable)

    let asyncThrows = reflect((() async throws -> Void).self) as! FunctionMetadata
    XCTAssertTrue(asyncThrows.flags.isAsync)
    XCTAssertTrue(asyncThrows.flags.throws)

    XCTAssertTrue((reflect((@MainActor () -> Void).self) as! FunctionMetadata).flags.hasGlobalActor)
  }

  static func testActorFlags() {
    let actorMetadata = reflectClass(FlagActor.self)!
    XCTAssertTrue(actorMetadata.isActor)
    XCTAssertTrue(actorMetadata.isDefaultActor)

    let plainMetadata = reflectClass(FlagPlainClass.self)!
    XCTAssertFalse(plainMetadata.isActor)
    XCTAssertFalse(plainMetadata.isDefaultActor)

    #if canImport(ObjectiveC)
    let nsObject = reflectClass(NSObject.self)!
    XCTAssertFalse(nsObject.isActor)
    XCTAssertFalse(nsObject.isDefaultActor)
    #endif
  }
}

extension EchoTests {
  func testMetadataFlags() {
    MetadataFlagsTests.testValueWitnessCopyability()
    MetadataFlagsTests.testFunctionFlags()
    MetadataFlagsTests.testActorFlags()
  }
}
