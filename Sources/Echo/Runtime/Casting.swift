//
//  Casting.swift
//  Echo
//
//  Copyright © 2026 Tevelee
//

/// Options accepted by Swift's low-level dynamic-cast runtime entry point.
///
/// Echo exposes this ABI representation for inspection and for clients that
/// already manage opaque storage correctly. It intentionally does not wrap
/// `swift_dynamicCast`: a safe generic wrapper cannot preserve the runtime's
/// copy, take, destruction, and noncopyable-value semantics.
public struct DynamicCastFlags: OptionSet, Sendable {
  /// The ABI bit representation.
  public let rawValue: UInt

  /// Creates a dynamic-cast flag set from its ABI representation.
  public init(rawValue: UInt) {
    self.rawValue = rawValue
  }

  /// The cast must not fail.
  public static let unconditional = Self(rawValue: 0x1)

  /// Transfer the source value into the result if the cast succeeds.
  public static let takeOnSuccess = Self(rawValue: 0x2)

  /// Destroy the source value if the cast fails.
  public static let destroyOnFailure = Self(rawValue: 0x4)

  /// Do not use conformances isolated to an actor or global actor.
  ///
  /// Swift uses this for casts to constraints such as `Sendable`, where an
  /// isolated conformance must not be treated as generally available.
  public static let prohibitIsolatedConformances = Self(rawValue: 0x8)
}
