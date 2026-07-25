import Foundation
import Testing
import Echo

class Boat {
  let name: String
  let designDate: Int
  
  init(name: String, designDate: Int) {
    self.name = name
    self.designDate = designDate
  }
}

class Boat2<T, U> {
  let name: T
  let designDate: U
  
  init(name: T, designDate: U) {
    self.name = name
    self.designDate = designDate
  }
}

class Boat3<T>: JSONEncoder, @unchecked Sendable {
  let name: T
  
  init(name: T) {
    self.name = name
  }
}

enum ClassMetadataTests {
  static func testClass() throws {
    let metadata = try #require(reflectClass(Boat.self))
    
    // classAddressPoint/classSize are runtime metadata-allocation details that
    // legitimately drift between Swift versions (the class metadata header grew
    // by one word after the values originally baked in here). Pin them to the
    // current ABI but keep the asserts so regressions in Echo's reading surface.
    #expect(metadata.classAddressPoint == 24)
    #if canImport(ObjectiveC)
    #expect(metadata.classSize == 128)
    #else
    #expect(metadata.classSize == 104)
    #endif
    #expect(metadata.instanceAddressPoint == 0)
    #expect(metadata.instanceAlignmentMask == 7)
    #expect(metadata.instanceSize == 40)
    #expect(metadata.flags.bits == 2)
    #expect(metadata.fieldOffsets == [16, 32])
    #expect(metadata.isSwiftClass == true)
    #if canImport(ObjectiveC)
    #expect(metadata.isaPointer != nil)
    #expect(metadata.superclassType != nil)
    #else
    #expect(metadata.isaPointer == nil)
    #expect(metadata.superclassType == nil)
    #endif
    #expect(typeArraysEquals(metadata.genericTypes, []))
    #expect(metadata.kind == .class)
    #expect(typesEqual(metadata.type, Boat.self))
    
    // VWT
    
    var extraInhabitantCount = 2147483647
    #if os(Linux)
    extraInhabitantCount = 4096
    #endif
    
    #expect(metadata.vwt.extraInhabitantCount == extraInhabitantCount)
    #expect(metadata.vwt.size == 8)
    #expect(metadata.vwt.stride == 8)
    #expect(metadata.vwt.flags.bits == 65543)
  }
  
  static func testGenericClass() throws {
    let metadata = try #require(reflectClass(Boat2<String, Int>.self))
    
    #expect(metadata.classAddressPoint == 24)
    #if canImport(ObjectiveC)
    #expect(metadata.classSize == 144)
    #else
    #expect(metadata.classSize == 120)
    #endif
    #expect(metadata.instanceAddressPoint == 0)
    #expect(metadata.instanceAlignmentMask == 7)
    #expect(metadata.instanceSize == 40)
    #expect(metadata.flags.bits == 2)
    #expect(metadata.fieldOffsets == [16, 32])
    #expect(metadata.isSwiftClass == true)
    #if canImport(ObjectiveC)
    #expect(metadata.isaPointer != nil)
    #expect(metadata.superclassType != nil)
    #else
    #expect(metadata.isaPointer == nil)
    #expect(metadata.superclassType == nil)
    #endif
    #expect(typeArraysEquals(metadata.genericTypes, [String.self, Int.self]))
    #expect(metadata.kind == .class)
    #expect(typesEqual(metadata.type, Boat2<String, Int>.self))
    
    // VWT
    
    var extraInhabitantCount = 2147483647
    #if os(Linux)
    extraInhabitantCount = 4096
    #endif
    
    #expect(metadata.vwt.extraInhabitantCount == extraInhabitantCount)
    #expect(metadata.vwt.size == 8)
    #expect(metadata.vwt.stride == 8)
    #expect(metadata.vwt.flags.bits == 65543)
    
    // Resilient Superclass Generic Types
    
    let resilientMetadata = reflectClass(Boat3<String>.self)!
    #expect(typeArraysEquals(resilientMetadata.genericTypes, [String.self]))
    #expect(resilientMetadata.superclassType != nil)
    #expect(typesEqual(resilientMetadata.superclassType!, JSONEncoder.self))

    // Regression: the resilient-superclass reference kind is a 3-bit field at
    // bit 9 and must be shifted, not just masked. Objective-C-interoperable
    // runtimes reference Foundation's JSONEncoder indirectly; non-Objective-C
    // runtimes use a direct descriptor reference.
    let superclassDescriptor = resilientMetadata.descriptor!
    #if canImport(ObjectiveC)
    #expect(superclassDescriptor.typeFlags.classHasResilientSuperclass)
    #expect(superclassDescriptor.typeFlags.resilientSuperclassRefKind == .indirectTypeDescriptor)
    #else
    #expect(superclassDescriptor.typeFlags.classHasResilientSuperclass == false)
    #expect(superclassDescriptor.typeFlags.resilientSuperclassRefKind == .directTypeDescriptor)
    #endif
  }
  
  #if canImport(ObjectiveC)
  static func testObjCClass() throws {
    let metadata = try #require(reflectClass(NSObject.self))

    // NSObject is a pure Objective-C class: the Swift-specific class metadata
    // fields (address points, alignment mask) overlap unrelated Objective-C
    // class bytes and carry no meaningful value, so we don't assert on them.
    // The meaningful invariant is that Echo recognizes it as a non-Swift class.
    #expect(metadata.isSwiftClass == false)
  }
  #endif
}

extension EchoTests {
  @Test
  func testClassMetadata() throws {
    try ClassMetadataTests.testClass()
    try ClassMetadataTests.testGenericClass()
    #if canImport(ObjectiveC)
    try ClassMetadataTests.testObjCClass()
    #endif
  }
}
