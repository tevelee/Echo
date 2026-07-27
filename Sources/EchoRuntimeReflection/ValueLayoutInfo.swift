import Echo

/// A domain-neutral summary of a Swift type's value-witness layout.
///
/// This view exposes layout and lifetime facts without leaking Echo's
/// pointer-backed `Metadata` or `ValueWitnessTable` representations. It does
/// not make a type supported for any particular ABI use; clients retain that
/// policy decision.
public struct ValueLayoutInfo {
  /// The reflected type.
  public let type: Any.Type

  /// The number of bytes occupied by a value.
  public let size: Int

  /// The number of bytes between adjacent values in contiguous storage.
  public let stride: Int

  /// The required alignment in bytes.
  public let alignment: Int

  /// Whether the value fits inline in an existential container.
  public let isValueInline: Bool

  /// Whether the value is plain old data.
  public let isPOD: Bool

  /// Whether the value can be moved with bitwise operations.
  public let isBitwiseTakable: Bool

  /// Whether the value supports copy operations.
  public let isCopyable: Bool

  /// Whether the value supports bitwise borrowing.
  public let isBitwiseBorrowable: Bool

  /// Whether the value must be addressed for lifetime dependencies.
  public let isAddressableForDependencies: Bool

  /// Whether the value witness table carries enum witnesses.
  public let hasEnumWitnesses: Bool

  /// Whether the runtime reports the value witness table as incomplete.
  public let isIncomplete: Bool

  /// Reflects the value-witness layout for `type`.
  public init(reflecting type: Any.Type) {
    let valueWitnesses = reflect(type).vwt
    let flags = valueWitnesses.flags

    self.type = type
    size = valueWitnesses.size
    stride = valueWitnesses.stride
    alignment = flags.alignment
    isValueInline = flags.isValueInline
    isPOD = flags.isPOD
    isBitwiseTakable = flags.isBitwiseTakable
    isCopyable = flags.isCopyable
    isBitwiseBorrowable = flags.isBitwiseBorrowable
    isAddressableForDependencies = flags.isAddressableForDependencies
    hasEnumWitnesses = flags.hasEnumWitnesses
    isIncomplete = flags.isIncomplete
  }
}
