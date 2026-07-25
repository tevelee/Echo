import Foundation
import Testing
import Echo

enum Colors {
  case blue
  case red
  case yellow
  case green(Bool)
}

extension EchoTests {
  @Test
  func testEnumDescriptor() {
    let metadata = reflectEnum(Colors.self)!
    #expect(metadata.descriptor.numEmptyCases == 3)
    #expect(metadata.descriptor.numPayloadCases == 1)
  }
}

