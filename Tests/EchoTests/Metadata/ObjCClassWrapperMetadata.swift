import Foundation
import Testing
import Echo

extension EchoTests {
  @Test
  func testObjCClassWrapperMetadata() throws {
    #if canImport(ObjectiveC)
    let metadata = try #require(reflect(NSObject.self) as? ObjCClassWrapperMetadata)
    
    // We compare strings here because comparing `NSObject.self` would compare
    // the objc class wrapper against class metadata.
    #expect("\(metadata.classType)" == "NSObject")
    #expect(metadata.kind == .objcClassWrapper)
    
    // VWT
    
    #expect(metadata.vwt.extraInhabitantCount == 2147483647)
    #expect(metadata.vwt.size == 8)
    #expect(metadata.vwt.stride == 8)
    #expect(metadata.vwt.flags.bits == 65543)
    #endif
  }
}
