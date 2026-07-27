import Echo

/// A domain-neutral view of Swift function-type metadata.
///
/// `FunctionTypeInfo` deliberately exposes source-level facts instead of
/// `Echo.FunctionMetadata`'s pointer-backed ABI layout. It remains subject to
/// the Swift runtime ABI supported by Echo, but gives consumers a stable
/// boundary for function effects and parameter conventions.
public struct FunctionTypeInfo {
  /// The original function type.
  public let type: Any.Type

  /// The function's result type.
  public let resultType: Any.Type

  /// The function's parameters in source order.
  public let parameters: [Parameter]

  /// The calling convention, if Echo understands its ABI value.
  public let convention: Convention?

  /// The unprocessed convention discriminator for diagnostics and
  /// fail-closed handling of future ABI values.
  public let rawConvention: UInt8

  /// The function's effects and isolation.
  public let effects: Effects

  /// Creates a reflection view when `type` is a Swift function type.
  public init?(reflecting type: Any.Type) {
    guard let metadata = reflect(type) as? FunctionMetadata else { return nil }

    self.type = type
    resultType = metadata.resultType

    let flags = metadata.flags
    rawConvention = UInt8(truncatingIfNeeded: (flags.bits & 0xFF0000) >> 16)
    convention = Convention(rawValue: rawConvention)

    let parameterFlags = metadata.paramFlags
    parameters = metadata.paramTypes.enumerated().map { index, type in
      Parameter(
        type: type,
        flags: parameterFlags.indices.contains(index) ? parameterFlags[index] : nil
      )
    }

    effects = Effects(metadata: metadata)
  }
}

extension FunctionTypeInfo {
  /// A function calling convention recognized by the current Swift ABI.
  public enum Convention: UInt8 {
    /// The native Swift calling convention.
    case swift = 0

    /// The Objective-C block calling convention.
    case block = 1

    /// The thin function calling convention.
    case thin = 2

    /// The C calling convention.
    case c = 3
  }

  /// A source-level parameter fact.
  public struct Parameter {
    /// The parameter type.
    public let type: Any.Type

    /// The parameter ownership, if Echo understands its ABI value.
    public let ownership: Ownership?

    /// The unprocessed ownership discriminator for diagnostics and
    /// fail-closed handling of future ABI values.
    public let rawOwnership: UInt8

    /// Whether the parameter is variadic.
    public let isVariadic: Bool

    /// Whether the parameter is an autoclosure.
    public let isAutoclosure: Bool

    /// Whether the parameter is excluded from automatic differentiation.
    public let isNoDerivative: Bool

    /// Whether the parameter is actor-isolated.
    public let isIsolated: Bool

    /// Whether the parameter transfers ownership with `sending`.
    public let isSending: Bool

    fileprivate init(type: Any.Type, flags: FunctionMetadata.ParamFlags?) {
      self.type = type

      let bits = flags?.bits ?? 0
      rawOwnership = UInt8(truncatingIfNeeded: bits & 0x7F)
      ownership = Ownership(rawValue: rawOwnership)
      isVariadic = bits & 0x80 != 0
      isAutoclosure = bits & 0x100 != 0
      isNoDerivative = bits & 0x200 != 0
      isIsolated = bits & 0x400 != 0
      isSending = bits & 0x800 != 0
    }
  }

  /// A parameter ownership convention recognized by the current Swift ABI.
  public enum Ownership: UInt8 {
    /// The runtime's default convention.
    case `default` = 0

    /// An exclusive `inout` parameter.
    case `inout` = 1

    /// A borrowing parameter.
    case borrowing = 2

    /// A consuming parameter.
    case consuming = 3
  }

  /// Function effects and isolation facts.
  public struct Effects {
    /// Whether the function is `async`.
    public let isAsync: Bool

    /// Whether the function throws an error.
    public let isThrowing: Bool

    /// Whether the function uses `throws(ErrorType)`.
    ///
    /// A typed error can be unavailable on runtimes where Swift does not make
    /// its metadata safe to read. In that case `isTypedThrows` remains true
    /// while `typedErrorType` is `nil`, so clients can reject the shape rather
    /// than treating it as an untyped throw.
    public let isTypedThrows: Bool

    /// The typed error, when the function uses `throws(ErrorType)`.
    public let typedErrorType: Any.Type?

    /// Whether the function is `@Sendable`.
    public let isSendable: Bool

    /// Whether the function is escaping.
    public let isEscaping: Bool

    /// Whether the function is differentiable.
    public let isDifferentiable: Bool

    /// The function's isolation.
    public let isolation: Isolation

    /// Whether the function is `@isolated(any)`.
    public var isIsolatedAny: Bool {
      guard case .isolatedAny = isolation else { return false }
      return true
    }

    /// Whether the function is `nonisolated(nonsending)`.
    public var isNonisolatedNonsending: Bool {
      guard case .nonisolatedNonsending = isolation else { return false }
      return true
    }

    /// The global actor type when the function is globally isolated.
    public var globalActorType: Any.Type? {
      guard case .globalActor(let type) = isolation else { return nil }
      return type
    }

    fileprivate init(metadata: FunctionMetadata) {
      let flags = metadata.flags
      isAsync = flags.isAsync
      isThrowing = flags.throws
      isTypedThrows = metadata.extendedFlags?.isTypedThrows == true
      #if os(Linux) && arch(x86_64)
        typedErrorType = nil
      #else
        typedErrorType = isTypedThrows ? metadata.thrownErrorType : nil
      #endif
      isSendable = flags.isSendable
      isEscaping = flags.isEscaping
      isDifferentiable = flags.isDifferentiable

      if let globalActorType = metadata.globalActorType {
        isolation = .globalActor(globalActorType)
      } else if let extendedFlags = metadata.extendedFlags {
        let rawIsolation = extendedFlags.bits & 0xE
        switch rawIsolation {
        case 0:
          isolation = .none
        case 0x2:
          isolation = .isolatedAny
        case 0x4:
          isolation = .nonisolatedNonsending
        default:
          isolation = .unknown(rawValue: rawIsolation)
        }
      } else {
        isolation = .none
      }
    }
  }

  /// The function's isolation, including future ABI values that cannot yet be
  /// interpreted safely.
  public enum Isolation {
    /// The function has no represented isolation.
    case none

    /// The function is isolated to a global actor.
    case globalActor(Any.Type)

    /// The function is `@isolated(any)`.
    case isolatedAny

    /// The function is `nonisolated(nonsending)`.
    case nonisolatedNonsending

    /// A future isolation encoding that Echo does not understand.
    case unknown(rawValue: UInt32)
  }
}
