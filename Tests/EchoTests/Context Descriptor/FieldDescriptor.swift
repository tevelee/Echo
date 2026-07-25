import Foundation
import Testing
import Echo

enum FieldDescriptorTests {
  
  class FieldTesting {
    weak var superman: Super?
    unowned let child1: Child
    unowned(unsafe) let child2: Child
    
    init(child1: Child, child2: Child) {
      self.child1 = child1
      self.child2 = child2
    }
  }
  
  static func testClass() throws {
    let metadata = reflectClass(FieldTesting.self)!
    let fields = metadata.descriptor!.fields
    
    #expect(fields.hasMangledTypeName)
    #expect(fields.kind == .class)
    
    let typeName = metadata.type(of: fields.mangledTypeName)!
    #expect(typesEqual(typeName, FieldTesting.self))
    
    #expect(fields.numFields == 3)
    
    #expect(fields.recordSize == 12)
    for (i, record) in fields.records.enumerated() {
      #expect(record.hasMangledTypeName)
      
      let varType = metadata.type(of: record.mangledTypeName)!
      
      switch i {
      case 0:
        #expect(typesEqual(varType, Super?.self))
      case 1...2:
        #expect(typesEqual(varType, Child.self))
      default:
        break
      }
      
      switch i {
      case 0:
        #expect(record.referenceStorage == .weak)
        #expect(record.flags.isVar)
      case 1:
        #expect(record.referenceStorage == .unowned)
        #expect(record.flags.isVar == false)
      case 2:
        #expect(record.referenceStorage == .unmanaged)
        #expect(record.flags.isVar == false)
      default:
        break
      }
      
      #expect(record.flags.isIndirectCase == false)
    }
  }
  
  enum ABC {
    case a, b, c
  }
  
  enum Color {
    indirect case color(Color)
    case hue(String)
  }
  
  static func testEnum() throws {
    let metadata = reflectEnum(ABC.self)!
    let fields = metadata.descriptor.fields
    
    #expect(fields.hasMangledTypeName)
    #expect(fields.kind == .enum)
    
    let typeName = metadata.type(of: fields.mangledTypeName)!
    #expect(typesEqual(typeName, ABC.self))
    
    #expect(fields.numFields == 3)
    
    #expect(fields.recordSize == 12)
    for record in fields.records {
      #expect(record.hasMangledTypeName == false)
      #expect(record.referenceStorage == .none)
    }
    
    let colorMetadata = reflectEnum(Color.self)!
    let colorFields = colorMetadata.descriptor.fields
    
    #expect(colorFields.kind == .multiPayloadEnum)
    
    for (i, record) in colorFields.records.enumerated() {
      switch i {
      case 0:
        #expect(record.flags.isIndirectCase)
        #expect(record.flags.isVar == false)
      case 1:
        #expect(record.flags.isIndirectCase == false)
        #expect(record.flags.isVar == false)
      default:
        break
      }
    }
    
  }
  
  static func testStruct() throws {
    let metadata = reflectStruct(Dog.self)!
    let fields = metadata.descriptor.fields
    
    #expect(fields.hasMangledTypeName)
    #expect(fields.kind == .struct)
    
    let typeName = metadata.type(of: fields.mangledTypeName)!
    #expect(typesEqual(typeName, Dog.self))
    
    #expect(fields.numFields == 2)
    
    #expect(fields.recordSize == 12)
    for (i, record) in fields.records.enumerated() {
      #expect(record.hasMangledTypeName)
      
      let varType = metadata.type(of: record.mangledTypeName)!
      
      switch i {
      case 0:
        #expect(typesEqual(varType, String.self))
      case 1:
        #expect(typesEqual(varType, Int.self))
      default:
        break
      }
      
      #expect(record.referenceStorage == .none)
      #expect(record.flags.isIndirectCase == false)
      #expect(record.flags.isVar == false)
    }
  }
}

extension EchoTests {
  @Test
  func testFieldDescriptor() throws {
    try FieldDescriptorTests.testClass()
    try FieldDescriptorTests.testEnum()
    try FieldDescriptorTests.testStruct()
  }
}

