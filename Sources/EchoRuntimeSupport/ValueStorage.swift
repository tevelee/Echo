import Echo

/// Owns temporary storage for one value described by Swift runtime metadata.
///
/// The storage pointer is intentionally exposed for low-level codecs. Callers
/// must transition its state after initializing, moving, or borrowing those
/// bytes; `ValueStorage` destroys only values it owns in the `.initialized`
/// state. It does not make a type valid for copying, ABI transport, or
/// existential storage.
public final class ValueStorage: @unchecked Sendable {
  /// Whether storage is uninitialized, borrowed, owned, or transferred.
  public enum State: Equatable, Sendable {
    /// The storage contains no initialized Swift value.
    case uninitialized

    /// The storage contains caller-owned bits that this instance will not
    /// destroy.
    case borrowedBits

    /// The storage owns one initialized Swift value.
    case initialized

    /// The owned value was moved out of the storage.
    case transferred
  }

  /// The type represented by the storage.
  public let type: Any.Type

  /// Raw storage for one value of `type`.
  public let storage: UnsafeMutableRawPointer

  /// The current ownership state of `storage`.
  public private(set) var state: State

  private let byteCount: Int
  private let deallocatesStorage: Bool

  /// The byte count required for temporary storage of one value, padded to a
  /// caller-requested minimum for register-word codecs.
  public static func byteCount(for type: Any.Type, minimum: Int = 1) -> Int {
    max(reflect(type).vwt.size, max(minimum, 1))
  }

  /// Allocates uninitialized, word-aligned temporary storage for one value.
  ///
  /// The caller owns deallocation and must destroy an initialized value before
  /// releasing the returned bytes.
  public static func allocate(
    for type: Any.Type,
    minimumByteCount: Int = 1
  ) -> UnsafeMutableRawPointer {
    let metadata = reflect(type)
    return UnsafeMutableRawPointer.allocate(
      byteCount: max(metadata.vwt.size, max(minimumByteCount, 1)),
      alignment: max(metadata.vwt.flags.alignment, MemoryLayout<UInt>.alignment)
    )
  }

  /// Allocates uninitialized, word-aligned storage for one value of `type`.
  ///
  /// `minimumByteCount` lets a register codec reserve complete words even for
  /// zero-size Swift values.
  public init(type: Any.Type, minimumByteCount: Int = 1) {
    self.type = type
    byteCount = Self.byteCount(for: type, minimum: minimumByteCount)
    storage = Self.allocate(for: type, minimumByteCount: minimumByteCount)
    state = .uninitialized
    deallocatesStorage = true
  }

  /// Allocates storage and initializes it with a copy of `value`'s concrete
  /// dynamic value.
  ///
  /// The storage owns the copied value and destroys it unless the caller moves
  /// or explicitly transfers that ownership.
  public convenience init(copying value: Any, minimumByteCount: Int = 1) {
    self.init(
      type: Swift.type(of: value),
      minimumByteCount: minimumByteCount
    )
    ValueOperations.initializeCopy(of: value, to: storage)
    markInitialized()
  }

  /// Views initialized caller-owned ABI bits without destroying or
  /// deallocating them.
  public init(borrowingBitsOf type: Any.Type, at storage: UnsafeMutableRawPointer) {
    self.type = type
    self.storage = storage
    byteCount = Self.byteCount(for: type)
    state = .borrowedBits
    deallocatesStorage = false
  }

  /// Owns an initialized value in caller-provided storage and destroys it when
  /// necessary, without deallocating those caller-owned bytes.
  public init(owningValueOf type: Any.Type, at storage: UnsafeMutableRawPointer) {
    self.type = type
    self.storage = storage
    byteCount = Self.byteCount(for: type)
    state = .initialized
    deallocatesStorage = false
  }

  /// Clears allocated storage and records that the resulting bits are
  /// borrowed rather than an initialized Swift value.
  public func zeroBorrowedBytes() {
    precondition(state == .uninitialized)
    storage.initializeMemory(as: UInt8.self, repeating: 0, count: byteCount)
    state = .borrowedBits
  }

  /// Records that a caller initialized a value in the storage.
  public func markInitialized() {
    precondition(state == .uninitialized || state == .borrowedBits)
    state = .initialized
  }

  /// Destroys the initialized value while retaining the storage allocation.
  public func destroyInitializedValue() {
    precondition(state == .initialized)
    ValueOperations.destroy(type, at: storage)
    state = .uninitialized
  }

  /// Moves the initialized value out of storage, transferring responsibility
  /// for its lifetime to the returned Swift value.
  public func moveInitializedValue<Value>(as _: Value.Type) -> Value {
    precondition(state == .initialized)
    precondition(
      ObjectIdentifier(Value.self) == ObjectIdentifier(type),
      "Value storage was moved as the wrong type."
    )
    let value = storage.assumingMemoryBound(to: Value.self).move()
    state = .transferred
    return value
  }

  /// Records that a caller moved the initialized value out through the raw
  /// storage pointer.
  public func markTransferred() {
    precondition(state == .initialized)
    state = .transferred
  }

  deinit {
    if state == .initialized {
      ValueOperations.destroy(type, at: storage)
    }
    if deallocatesStorage {
      storage.deallocate()
    }
  }
}
