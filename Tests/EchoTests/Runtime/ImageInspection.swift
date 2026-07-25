import Foundation
import Testing
import Echo

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
}
