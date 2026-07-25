import Foundation
import Testing
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
  @Test
  func testBoxRuntimeFunctions() {
    var wasDeinitialized = false
    exerciseBoxRuntimeFunctions {
      wasDeinitialized = true
    }
    #expect(wasDeinitialized)
  }

  private func exerciseBoxRuntimeFunctions(onDeinit: @escaping () -> Void) {
    let metadata = reflect(BoxedValue.self)
    let allocated = swift_allocBox(for: metadata)
    #expect(Int(bitPattern: allocated.buffer) & metadata.vwt.flags.alignmentMask == 0)
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

    #expect(Int(bitPattern: UnsafeRawPointer(unique.heapObj)) != sharedHeapObject)
    #expect(container(for: original).data.0 == Int(bitPattern: UnsafeRawPointer(unique.heapObj)))
    #expect((original as! BoxedValue).reference.value == 42)
    #expect((copy as! BoxedValue).reference.value == 42)
    original = ()
    copy = ()
  }
}
