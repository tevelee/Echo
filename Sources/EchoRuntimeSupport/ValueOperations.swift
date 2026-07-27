import Echo

/// Performs low-level value-witness operations using a reflected Swift type.
///
/// These operations preserve the runtime's ownership rules but do not make a
/// value valid for a particular ABI transport or storage representation.
public enum ValueOperations {
  /// Initializes `destination` by copying the concrete value stored in `value`.
  ///
  /// This opens `value`'s existential container, preserving its dynamic type
  /// and ownership. `destination` must be uninitialized storage suitable for
  /// the returned type. The caller retains ownership of `value`.
  @discardableResult
  public static func initializeCopy(
    of value: Any,
    to destination: UnsafeMutableRawPointer
  ) -> Any.Type {
    var container = Echo.container(for: value)
    let type = container.metadata.type
    initializeCopy(
      of: type,
      from: container.projectValue(),
      to: destination
    )
    return type
  }

  /// Initializes `destination` by copying the initialized value at `source`.
  ///
  /// `destination` must be uninitialized storage suitable for one value of
  /// `type`. The caller retains ownership of `source`.
  public static func initializeCopy(
    of type: Any.Type,
    from source: UnsafeRawPointer,
    to destination: UnsafeMutableRawPointer
  ) {
    reflect(type).vwt.initializeWithCopy(
      destination,
      UnsafeMutableRawPointer(mutating: source)
    )
  }

  /// Destroys the initialized value at `storage` without deallocating it.
  ///
  /// The caller must not destroy the same value again and retains ownership of
  /// the storage allocation itself.
  public static func destroy(
    _ type: Any.Type,
    at storage: UnsafeMutableRawPointer
  ) {
    reflect(type).vwt.destroy(storage)
  }
}
