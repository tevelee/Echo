import Foundation
import Testing
import Echo

func add(_ x: Int, _ y: Int...) -> Int {
  fatalError()
}

extension EchoTests {
  @Test
  func testFunctionMetadata() throws {
    let metadata = try #require(reflect(add(_:_:)) as? FunctionMetadata)
    
    #expect(metadata.flags.numParams == 2)
    #expect(metadata.flags.convention == .swift)
    #expect(metadata.flags.throws == false)
    #expect(metadata.flags.hasParamFlags)
    #expect(metadata.flags.isEscaping)
    #expect(typeArraysEquals(metadata.paramTypes, [Int.self, Int.self]))
    #expect(typesEqual(metadata.resultType, Int.self))
    #expect(metadata.kind == .function)
    
    for (i, paramFlag) in metadata.paramFlags.enumerated() {
      switch i {
      case 0:
        #expect(paramFlag.bits == 0)
      case 1:
        #expect(paramFlag.bits == 128)
      default:
        fatalError()
      }
    }
    
    // VWT
    
    var extraInhabitantCount = 2147483647
    #if os(Linux)
    extraInhabitantCount = 4096
    #endif
    
    #expect(metadata.vwt.extraInhabitantCount == extraInhabitantCount)
    #expect(metadata.vwt.size == 16)
    #expect(metadata.vwt.stride == 16)
    #expect(metadata.vwt.flags.bits == 65543)
  }
}
