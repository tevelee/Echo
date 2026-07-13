import XCTest
import Echo

struct AnonymousFoo {
  private struct AnonymousBar {}
  private struct AnonymousGenericBar<T: Equatable> {}
  
  static func test() throws {
    let metadata = reflectStruct(AnonymousBar.self)!
    let parent = metadata.descriptor.parent! as! AnonymousDescriptor
    try assertMangledName(
      of: parent,
      equals: "$s9EchoTests12AnonymousFooV0C3Bar33_16BDE84827F25937B00C6B35A30DC536LLV"
    )
  }
  
  static func testGeneric() throws {
    let metadata = reflectStruct(AnonymousGenericBar<Int>.self)!
    let parent = metadata.descriptor.parent! as! AnonymousDescriptor
    try assertMangledName(
      of: parent,
      equals: "$s9EchoTests12AnonymousFooV0C10GenericBar33_16BDE84827F25937B00C6B35A30DC536LLV"
    )
  }

  private static func assertMangledName(
    of descriptor: AnonymousDescriptor,
    equals expected: String
  ) throws {
    #if DEBUG
    XCTAssertTrue(descriptor.anonymousFlags.hasMangledName)
    XCTAssertEqual(try XCTUnwrap(descriptor.mangledName), expected)
    #else
    // Optimized builds may omit the optional debugging name entirely.
    if descriptor.anonymousFlags.hasMangledName {
      XCTAssertEqual(try XCTUnwrap(descriptor.mangledName), expected)
    } else {
      XCTAssertNil(descriptor.mangledName)
    }
    #endif
  }
}

extension EchoTests {
  func testAnonymousDescriptor() throws {
    try AnonymousFoo.test()
    try AnonymousFoo.testGeneric()
  }
}
