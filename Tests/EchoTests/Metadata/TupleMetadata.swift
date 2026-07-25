import Foundation
import Testing
import Echo

extension EchoTests {
  @Test
  func testTupleMetadata() throws {
    let metadata = try #require(reflect((Int, String).self) as? TupleMetadata)
    
    #expect(metadata.numElements == 2)
    
    for i in 0 ..< metadata.numElements {
      switch i {
      case 0:
        #expect(metadata.labels[i] == "0")
        #expect(typesEqual(metadata.elements[i].type, Int.self))
        #expect(metadata.elements[i].offset == 0)
      case 1:
        #expect(metadata.labels[i] == "1")
        #expect(typesEqual(metadata.elements[i].type, String.self))
        #expect(metadata.elements[i].offset == MemoryLayout<Int>.size)
      default:
        fatalError()
      }
    }
    
    // LABELS
    
    let _metadata = reflect((age: Int, name: String).self) as! TupleMetadata
    #expect(_metadata.labels == ["age", "name"])
    
    // VWT
    
    var extraInhabitantCount = 2147483647
    #if os(Linux)
    extraInhabitantCount = 4096
    #endif
    
    #expect(metadata.vwt.extraInhabitantCount == extraInhabitantCount)
    #expect(metadata.vwt.size == 24)
    #expect(metadata.vwt.stride == 24)
    #expect(metadata.vwt.flags.bits == 65543)
  }
}
