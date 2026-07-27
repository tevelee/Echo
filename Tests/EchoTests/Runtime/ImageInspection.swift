import Foundation
import Testing
@testable import Echo

private dynamic func imageInspectionReplacementTarget() -> Int {
  41
}

@_dynamicReplacement(for: imageInspectionReplacementTarget())
private func imageInspectionReplacement() -> Int {
  42
}

enum ImageInspectionTests {
  static func testConformances() throws {
    // Echo Types
    
    let metadata = reflectStruct(StructMetadata.self)!
    #expect(metadata.conformances.count == 4)
    
    // Stdlib types
    
    let int = reflectStruct(Int.self)!
    
    var intConfCount = 27
    #if os(Linux)
    intConfCount = 25
    #endif
    
    #expect(int.conformances.count >= intConfCount)
  }
  
  static func testProtos() throws {
    let protos = Echo.protocols
    
    // Echo Protos
    
    var echoFound = false
    for proto in protos {
      guard let module = proto.parent as? ModuleDescriptor else {
        continue
      }
      
      guard module.name == "Echo", proto.name == "Metadata" else {
        continue
      }
      
      echoFound = true
    }
    
    #expect(echoFound)
    
    // Stdlib protos
    
    var stdlibFound = false
    for proto in protos {
      guard let module = proto.parent as? ModuleDescriptor else {
        continue
      }
      
      guard module.name == "Swift", proto.name == "RandomNumberGenerator" else {
        continue
      }
      
      stdlibFound = true
    }
    
    #expect(stdlibFound)
  }
  
  static func testTypes() throws {
    let types = Echo.types
    
    // Echo Protos
    
    var echoFound = false
    for type in types {
      guard let module = type.parent as? ModuleDescriptor else {
        continue
      }
      
      guard let structDescriptor = type as? StructDescriptor else {
        continue
      }
      
      guard module.name == "Echo", structDescriptor.name == "StructMetadata" else {
        continue
      }
      
      echoFound = true
    }
    
    #expect(echoFound)
    
    // Stdlib protos
    
    var stdlibFound = false
    for type in types {
      guard let module = type.parent as? ModuleDescriptor else {
        continue
      }
      
      guard let structDescriptor = type as? StructDescriptor else {
        continue
      }
      
      guard module.name == "Swift", structDescriptor.name == "Int" else {
        continue
      }
      
      stdlibFound = true
    }
    
    #expect(stdlibFound)
  }
}

extension EchoTests {
  @Test
  func testImageInspection() throws {
    try ImageInspectionTests.testConformances()
    try ImageInspectionTests.testProtos()
    try ImageInspectionTests.testTypes()
  }

  @Test
  func imageInspectionDecodesModernImageRecords() throws {
    // Registered image records remain valid for their image's lifetime. Keep
    // this synthetic image allocation alive for the process lifetime too.
    let storage = UnsafeMutableRawPointer.allocate(byteCount: 512, alignment: 8)
    storage.initializeMemory(as: UInt8.self, repeating: 0, count: 512)

    // swift5_replace: one automatic entry pointing at a scope with one
    // function replacement descriptor.
    storage.storeBytes(of: UInt32(0), toByteOffset: 0, as: UInt32.self)
    storage.storeBytes(of: UInt32(1), toByteOffset: 4, as: UInt32.self)
    storage.storeBytes(of: Int32(56), toByteOffset: 8, as: Int32.self)

    storage.storeBytes(of: UInt32(0), toByteOffset: 64, as: UInt32.self)
    storage.storeBytes(of: UInt32(1), toByteOffset: 68, as: UInt32.self)
    storage.storeBytes(of: Int32(24), toByteOffset: 72, as: Int32.self)
    storage.storeBytes(of: Int32(68), toByteOffset: 76, as: Int32.self)
    storage.storeBytes(of: Int32(40), toByteOffset: 80, as: Int32.self)
    storage.storeBytes(of: UInt32(1), toByteOffset: 84, as: UInt32.self)
    storage.storeBytes(of: Int32(24), toByteOffset: 96, as: Int32.self)
    storage.storeBytes(of: UInt32(1 << 16), toByteOffset: 100, as: UInt32.self)

    registerDynamicReplacementScopes(section: UnsafeRawPointer(storage), size: 16)

    let scope = try #require(
      dynamicReplacementScopes.first { $0.ptr == UnsafeRawPointer(storage + 64) }
    )
    let replacement = try #require(scope.replacementDescriptors.first)
    let replacementKey = try #require(replacement.replacedFunctionKey)
    #expect(replacement.shouldChain)
    #expect(replacement.replacementFunction == UnsafeRawPointer(storage + 144))
    #expect(replacementKey.isAsync)
    #expect(replacementKey.root?.ptr == UnsafeRawPointer(storage + 120))

    // swift5_replac2: one original/replacement opaque descriptor pair.
    storage.storeBytes(of: UInt32(0), toByteOffset: 160, as: UInt32.self)
    storage.storeBytes(of: UInt32(1), toByteOffset: 164, as: UInt32.self)
    storage.storeBytes(of: Int32(24), toByteOffset: 168, as: Int32.self)
    storage.storeBytes(of: Int32(36), toByteOffset: 172, as: Int32.self)
    storage.storeBytes(
      of: ContextDescriptorFlags(bits: UInt32(ContextDescriptorKind.opaqueType.rawValue)),
      toByteOffset: 192,
      as: ContextDescriptorFlags.self
    )
    storage.storeBytes(
      of: ContextDescriptorFlags(bits: UInt32(ContextDescriptorKind.opaqueType.rawValue)),
      toByteOffset: 208,
      as: ContextDescriptorFlags.self
    )

    registerOpaqueTypeReplacements(section: UnsafeRawPointer(storage + 160), size: 16)

    let opaqueReplacement = try #require(
      opaqueTypeReplacements.first { $0.ptr == UnsafeRawPointer(storage + 168) }
    )
    #expect(opaqueReplacement.original?.ptr == UnsafeRawPointer(storage + 192))
    #expect(opaqueReplacement.replacement?.ptr == UnsafeRawPointer(storage + 208))

    // swift5_accessible_functions: an entry has four relative references and
    // a single flag word. These function pointers are intentionally not called.
    storage.storeBytes(of: Int32(64), toByteOffset: 256, as: Int32.self)
    storage.storeBytes(of: Int32(140), toByteOffset: 260, as: Int32.self)
    storage.storeBytes(of: Int32(88), toByteOffset: 264, as: Int32.self)
    storage.storeBytes(of: Int32(116), toByteOffset: 268, as: Int32.self)
    storage.storeBytes(of: UInt32(1), toByteOffset: 272, as: UInt32.self)
    storage.storeBytes(of: UInt8(ascii: "$"), toByteOffset: 320, as: UInt8.self)
    storage.storeBytes(of: UInt8(ascii: "s"), toByteOffset: 321, as: UInt8.self)
    storage.storeBytes(of: UInt8(ascii: "4"), toByteOffset: 322, as: UInt8.self)
    storage.storeBytes(of: UInt8(ascii: "T"), toByteOffset: 323, as: UInt8.self)
    storage.storeBytes(of: UInt8(ascii: "e"), toByteOffset: 324, as: UInt8.self)
    storage.storeBytes(of: UInt8(ascii: "s"), toByteOffset: 325, as: UInt8.self)
    storage.storeBytes(of: UInt8(ascii: "t"), toByteOffset: 326, as: UInt8.self)
    storage.storeBytes(of: UInt8(ascii: "y"), toByteOffset: 327, as: UInt8.self)
    storage.storeBytes(of: UInt8(0), toByteOffset: 328, as: UInt8.self)
    storage.storeBytes(of: UInt8(ascii: "y"), toByteOffset: 352, as: UInt8.self)
    storage.storeBytes(of: UInt8(0), toByteOffset: 353, as: UInt8.self)
    storage.storeBytes(of: UInt32(1), toByteOffset: 400, as: UInt32.self)
    storage.storeBytes(of: UInt16(1), toByteOffset: 404, as: UInt16.self)
    storage.storeBytes(of: UInt8(0), toByteOffset: 406, as: UInt8.self)

    registerAccessibleFunctions(
      section: UnsafeRawPointer(storage + 256),
      size: MemoryLayout<_AccessibleFunction>.stride
    )

    let function = try #require(
      accessibleFunctions.first { $0.ptr == UnsafeRawPointer(storage + 256) }
    )
    let genericEnvironment = try #require(function.genericEnvironment)
    #expect(String(cString: function.mangledName.assumingMemoryBound(to: CChar.self)) == "$s4Testy")
    #expect(genericEnvironment.genericParameterCounts == [1])
    #expect(genericEnvironment.genericParameters.map(\.kind) == [.type])
    #expect(genericEnvironment.requirements.isEmpty)
    #expect(function.function == UnsafeRawPointer(storage + 384))
    #expect(function.flags.isDistributed)
  }

  @Test
  func imageInspectionFindsCompilerDynamicReplacement() {
    #expect(imageInspectionReplacementTarget() == 42)
    #expect(dynamicReplacementScopes.isEmpty == false)
  }

  @Test
  func imageInspectionStorageDeduplicatesAddressSnapshots() {
    let storage = ImageInspectionStorage()
    let first = UnsafeRawPointer(bitPattern: 0x1000)!
    let second = UnsafeRawPointer(bitPattern: 0x2000)!

    storage.insertProtocol(first)
    storage.insertProtocol(first)
    let snapshot = storage.protocols
    storage.insertProtocol(second)

    #expect(snapshot == [first])
    #expect(Set(storage.protocols) == Set([first, second]))

    storage.insertType(first)
    storage.insertType(first)
    storage.insertDynamicReplacementScope(first)
    storage.insertDynamicReplacementScope(first)
    storage.insertOpaqueTypeReplacement(first)
    storage.insertOpaqueTypeReplacement(first)
    storage.insertAccessibleFunction(first)
    storage.insertAccessibleFunction(first)

    #expect(storage.types == [first])
    #expect(storage.dynamicReplacementScopes == [first])
    #expect(storage.opaqueTypeReplacements == [first])
    #expect(storage.accessibleFunctions == [first])
  }
}
