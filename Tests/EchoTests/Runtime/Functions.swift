import XCTest
@testable import Echo

private final class BoxedReference {
  let value: Int
  let onDeinit: () -> Void

  init(value: Int, onDeinit: @escaping () -> Void) {
    self.value = value
    self.onDeinit = onDeinit
  }

  deinit {
    onDeinit()
  }
}

private struct BoxedValue {
  let reference: BoxedReference
  let padding: (Int, Int, Int)
}

extension EchoTests {
  func testBoxRuntimeFunctions() {
    var wasDeinitialized = false
    exerciseBoxRuntimeFunctions {
      wasDeinitialized = true
    }
    XCTAssertTrue(wasDeinitialized)
  }

  private func exerciseBoxRuntimeFunctions(onDeinit: @escaping () -> Void) {
    let metadata = reflect(BoxedValue.self)
    let allocated = swift_allocBox(for: metadata)
    XCTAssertEqual(
      Int(bitPattern: allocated.buffer) & metadata.vwt.flags.alignmentMask,
      0
    )
    _swift_deallocUninitializedBox(allocated.heapObj)

    var original: Any = BoxedValue(
      reference: BoxedReference(value: 42, onDeinit: onDeinit),
      padding: (1, 2, 3)
    )
    var copy = original
    let sharedHeapObject = container(for: copy).data.0

    let unique = withUnsafeMutablePointer(to: &original) { existential in
      _swift_makeBoxUnique(
        for: UnsafeRawPointer(existential),
        type: BoxedValue.self,
        alignMask: UInt(metadata.vwt.flags.alignmentMask)
      )
    }

    XCTAssertNotEqual(
      Int(bitPattern: UnsafeRawPointer(unique.heapObj)),
      sharedHeapObject
    )
    XCTAssertEqual(
      container(for: original).data.0,
      Int(bitPattern: UnsafeRawPointer(unique.heapObj))
    )
    XCTAssertEqual((original as! BoxedValue).reference.value, 42)
    XCTAssertEqual((copy as! BoxedValue).reference.value, 42)
    original = ()
    copy = ()
  }
}
