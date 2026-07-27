import EchoRuntimeSupport
import Testing

private final class LifetimeToken {}

private final class WeakReference<Value: AnyObject> {
  weak var value: Value?

  init(_ value: Value?) {
    self.value = value
  }
}

private struct OwnedValue {
  let token: LifetimeToken
}

@Suite
struct ValueStorageTests {
  @Test
  func reservesStorageForZeroSizeValues() {
    #expect(ValueStorage.byteCount(for: Void.self, minimum: 0) >= 1)
  }

  @Test
  func borrowedBitsRemainCallerOwned() {
    var value = 42
    withUnsafeMutablePointer(to: &value) { pointer in
      let storage = ValueStorage(
        borrowingBitsOf: Int.self,
        at: UnsafeMutableRawPointer(pointer)
      )

      #expect(storage.state == .borrowedBits)
      #expect(storage.storage.load(as: Int.self) == 42)
    }
    #expect(value == 42)
  }

  @Test
  func initializedValueIsDestroyedExactlyOnce() {
    var token: LifetimeToken? = LifetimeToken()
    let weakToken = WeakReference(token)
    let storage = ValueStorage(type: OwnedValue.self)
    storage.storage.assumingMemoryBound(to: OwnedValue.self)
      .initialize(to: OwnedValue(token: token!))
    storage.markInitialized()
    token = nil

    #expect(weakToken.value != nil)
    storage.destroyInitializedValue()
    #expect(storage.state == .uninitialized)
    #expect(weakToken.value == nil)
  }

  @Test
  func movedValueLeavesTransferredStorage() {
    let storage = ValueStorage(type: Int.self)
    storage.storage.assumingMemoryBound(to: Int.self).initialize(to: 42)
    storage.markInitialized()

    let value = storage.moveInitializedValue(as: Int.self)

    #expect(value == 42)
    #expect(storage.state == .transferred)
  }
}
