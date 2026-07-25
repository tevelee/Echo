import Foundation
import Testing
import Echo

struct Cat {
  let name: String
  let age: Int
}

struct Cat2<T, U> {
  let name: T
  let age: U
}

enum StructMetadataTests {
  static func testStruct() throws {
    let metadata = try #require(reflectStruct(Cat.self))
    
    #expect(metadata.fieldOffsets == [0, 16])
    #expect(typeArraysEquals(metadata.genericTypes, []))
    #expect(metadata.kind == .struct)
    #expect(typesEqual(metadata.type, Cat.self))
    
    // VWT
    
    var extraInhabitantCount = 2147483647
    #if os(Linux)
    extraInhabitantCount = 4096
    #endif
    
    #expect(metadata.vwt.extraInhabitantCount == extraInhabitantCount)
    #expect(metadata.vwt.size == 24)
    #expect(metadata.vwt.stride == 24)
    assertStringAndIntLayoutFlags(metadata.vwt.flags)
    
    // type(of:)
    
    for (i, record) in metadata.descriptor.fields.records.enumerated() {
      #expect(record.hasMangledTypeName)
      
      switch i {
      case 0:
        #expect(typesEqual(metadata.type(of: record.mangledTypeName), String.self))
      case 1:
        #expect(typesEqual(metadata.type(of: record.mangledTypeName), Int.self))
      default:
        fatalError()
      }
    }
  }
  
  static func testGenericStruct() throws {
    let metadata = try #require(reflectStruct(Cat2<String, Int>.self))
    
    #expect(metadata.fieldOffsets == [0, 16])
    #expect(typeArraysEquals(metadata.genericTypes, [String.self, Int.self]))
    #expect(metadata.kind == .struct)
    #expect(typesEqual(metadata.type, Cat2<String, Int>.self))
    
    // VWT
    
    var extraInhabitantCount = 2147483647
    #if os(Linux)
    extraInhabitantCount = 4096
    #endif
    
    #expect(metadata.vwt.extraInhabitantCount == extraInhabitantCount)
    #expect(metadata.vwt.size == 24)
    #expect(metadata.vwt.stride == 24)
    assertStringAndIntLayoutFlags(metadata.vwt.flags)
  }

  private static func assertStringAndIntLayoutFlags(
    _ flags: ValueWitnessTable.Flags
  ) {
    // New runtimes may add flags that do not change these layout semantics.
    #expect(flags.alignment == 8)
    #expect(flags.isValueInline)
    #expect(flags.isPOD == false)
    #expect(flags.isBitwiseTakable)
    #expect(flags.hasEnumWitnesses == false)
    #expect(flags.isIncomplete == false)
  }
}

extension EchoTests {
  @Test
  func testStructMetadata() throws {
    try StructMetadataTests.testStruct()
    try StructMetadataTests.testGenericStruct()
  }
}
