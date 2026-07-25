import Foundation
import Testing
import Echo

enum Colors2<T> {
  case red
  case blue(T)
  indirect case green(Colors2<T>)
}

enum EnumMetadataTests {
  static func testEnum() throws {
    let metadata = try #require(reflectEnum(Colors.self))
    
    #expect(metadata.kind == .enum || metadata.kind == .optional)
    #expect(metadata.fieldOffsets == [])
    #expect(typeArraysEquals(metadata.genericTypes, []))
    
    // VWT
    
    #expect(metadata.vwt.extraInhabitantCount == 251)
    #expect(metadata.vwt.size == 1)
    #expect(metadata.vwt.stride == 1)
    #expect(metadata.vwt.flags.bits == 2097152)
    
    // Enum VWT
    
    withUnsafePointer(to: Colors.blue) {
      #expect(metadata.enumVwt.getEnumTag(for: $0) == 1)
    }
  }
  
  static func testGenericEnum() throws {
    let metadata = try #require(reflectEnum(Colors2<Int>.self))
    
    #expect(metadata.kind == .enum || metadata.kind == .optional)
    #expect(metadata.fieldOffsets == [])
    #expect(typeArraysEquals(metadata.genericTypes, [Int.self]))
    
    // VWT
    
    #expect(metadata.vwt.extraInhabitantCount == 253)
    #expect(metadata.vwt.size == 9)
    #expect(metadata.vwt.stride == 16)
    #expect(metadata.vwt.flags.bits == 2162695)
    
    // Enum VWT
    
    withUnsafePointer(to: Colors2<Int>.blue(128)) {
      #expect(metadata.enumVwt.getEnumTag(for: $0) == 0)
    }
  }
}

extension EchoTests {
  @Test
  func testEnumMetadata() throws {
    try EnumMetadataTests.testEnum()
    try EnumMetadataTests.testGenericEnum()
  }
}
