//
//  Echo.swift
//  Echo
//
//  Created by Alejandro Alonso
//  Copyright © 2019 - 2021 Alejandro Alonso. All rights reserved.
//

//===----------------------------------------------------------------------===//
// Generic Reflect
//===----------------------------------------------------------------------===//

/// The main entry point to grab type metadata from some metatype.
/// - Parameter type: Metatype to get metadata from.
/// - Returns: `Metadata` for the given type.
public func reflect(_ type: Any.Type) -> Metadata {
  let ptr = unsafeBitCast(type, to: UnsafeRawPointer.self)
  
  return getMetadata(at: ptr)
}

/// Reflects metadata for a type that may be noncopyable.
///
/// `~Copyable` metatypes cannot be converted to `Any.Type`; this overload
/// preserves their runtime metadata pointer without requiring that conversion.
public func reflect<T: ~Copyable>(_ type: T.Type) -> Metadata {
  getMetadata(at: unsafeBitCast(type, to: UnsafeRawPointer.self))
}

/// The main entry point to grab type metadata from some instance.
/// - Parameter instance: Any instance value to get metadata from.
/// - Returns: `Metadata` for the given instance.
public func reflect(_ instance: Any) -> Metadata {
  container(for: instance).metadata
}

//===----------------------------------------------------------------------===//
// Class Reflect
//===----------------------------------------------------------------------===//

/// The main entry point to grab a `class`'s metadata from some metatype that
/// represents a `class`.
/// - Parameter type: Metatype to get struct metadata from.
/// - Returns: `ClassMetadata` for the given metatype.
public func reflectClass(_ type: Any.Type) -> ClassMetadata? {
  let ptr = unsafeBitCast(type, to: UnsafeRawPointer.self)
  let kind = getMetadataKind(at: ptr)
  
  guard kind == .class || kind == .objcClassWrapper else {
    return nil
  }
  
  if kind == .class {
    return ClassMetadata(ptr: ptr)
  } else {
    return ObjCClassWrapperMetadata(ptr: ptr).classMetadata
  }
}

/// The main entry point to grab a `class`'s metadata from some instance.
/// - Parameter instance: Any instance value of a `class` to get metadata from.
/// - Returns: `ClassMetadata` for the given instance.
public func reflectClass(_ instance: Any) -> ClassMetadata? {
  let box = container(for: instance)
  
  guard box.metadata.kind == .class ||
          box.metadata.kind == .objcClassWrapper else {
    return nil
  }
  
  // I explicitly construct a new class metadata value here because I don't
  // want to have to cast the existential Metadata to ClassMetadata for
  // performance reasons.
  if box.metadata.kind == .class {
    return ClassMetadata(ptr: box.metadata.ptr)
  } else {
    return ObjCClassWrapperMetadata(ptr: box.metadata.ptr).classMetadata
  }
}

//===----------------------------------------------------------------------===//
// Enum Reflect
//===----------------------------------------------------------------------===//

/// The main entry point to grab an `enum`'s metadata from some metatype that
/// represents a `enum`.
/// - Parameter type: Metatype to get `enum` metadata from.
/// - Returns: `EnumMetadata` for the given metatype.
public func reflectEnum(_ type: Any.Type) -> EnumMetadata? {
  let ptr = unsafeBitCast(type, to: UnsafeRawPointer.self)
  let kind = getMetadataKind(at: ptr)
  
  guard kind == .enum || kind == .optional else {
    return nil
  }
  
  return EnumMetadata(ptr: ptr)
}

/// Reflects enum metadata for a type that may be noncopyable.
public func reflectEnum<T: ~Copyable>(_ type: T.Type) -> EnumMetadata? {
  let ptr = unsafeBitCast(type, to: UnsafeRawPointer.self)
  guard getMetadataKind(at: ptr) == .enum || getMetadataKind(at: ptr) == .optional else {
    return nil
  }
  return EnumMetadata(ptr: ptr)
}

/// The main entry point to grab a `enum`'s metadata from some instance.
/// - Parameter instance: Any instance value of a `enum` to get metadata from.
/// - Returns: `EnumMetadata` for the given instance.
public func reflectEnum(_ instance: Any) -> EnumMetadata? {
  let box = container(for: instance)
  
  guard box.metadata.kind == .enum || box.metadata.kind == .optional else {
    return nil
  }
  
  // I explicitly construct a new enum metadata value here because I don't
  // want to have to cast the existential Metadata to EnumMetadata for
  // performance reasons.
  return EnumMetadata(ptr: box.metadata.ptr)
}

//===----------------------------------------------------------------------===//
// Struct Reflect
//===----------------------------------------------------------------------===//

/// The main entry point to grab a `struct`'s metadata from some metatype that
/// represents a `struct`.
/// - Parameter type: Metatype to get struct metadata from.
/// - Returns: `StructMetadata` for the given metatype.
public func reflectStruct(_ type: Any.Type) -> StructMetadata? {
  let ptr = unsafeBitCast(type, to: UnsafeRawPointer.self)
  
  guard getMetadataKind(at: ptr) == .struct else {
    return nil
  }
  
  return StructMetadata(ptr: ptr)
}

/// Reflects struct metadata for a type that may be noncopyable.
public func reflectStruct<T: ~Copyable>(_ type: T.Type) -> StructMetadata? {
  let ptr = unsafeBitCast(type, to: UnsafeRawPointer.self)
  guard getMetadataKind(at: ptr) == .struct else { return nil }
  return StructMetadata(ptr: ptr)
}

/// The main entry point to grab a `struct`'s metadata from some instance.
/// - Parameter instance: Any instance value of a `struct` to get metadata from.
/// - Returns: `StructMetadata` for the given instance.
public func reflectStruct(_ instance: Any) -> StructMetadata? {
  let box = container(for: instance)
  
  guard box.metadata.kind == .struct else {
    return nil
  }
  
  // I explicitly construct a new struct metadata value here because I don't
  // want to have to cast the existential Metadata to StructMetadata for
  // performance reasons.
  return StructMetadata(ptr: box.metadata.ptr)
}

//===----------------------------------------------------------------------===//
// Container
//===----------------------------------------------------------------------===//

/// Given an `Any` value, return the container that represents the value.
/// - Parameter instance: Some instance of `Any`
/// - Returns: The existential container that said instance represents.
public func container(for instance: Any) -> AnyExistentialContainer {
  // Swift 6 may implicitly open an existential passed as `Any`. Re-erasing it
  // into a statically-known wrapper preserves the four-word existential
  // container before projecting its ABI layout.
  struct Container {
    let value: Any
  }

  var box = unsafeBitCast(Container(value: instance), to: AnyExistentialContainer.self)
  
  while box.type == Any.self {
    box = box.projectValue().load(as: AnyExistentialContainer.self)
  }
  
  return box
}

/// Projects an erased value's dynamic type and initialized storage for the
/// duration of `body`.
///
/// The projected pointer is valid only while `body` executes. This provides a
/// scoped way to perform an operation selected by the value's dynamic type;
/// it does not materialize the value for a different existential or ABI
/// representation.
///
/// - Parameters:
///   - instance: An erased Swift value to project.
///   - body: Receives the value's dynamic type and initialized storage.
/// - Returns: The result of `body`.
public func withProjectedValue<Result>(
  of instance: Any,
  _ body: (Any.Type, UnsafeRawPointer) throws -> Result
) rethrows -> Result {
  var box = container(for: instance)
  return try body(box.metadata.type, box.projectValue())
}

/// Projects erased values' dynamic types and initialized storage for the
/// duration of `body`.
///
/// Each storage pointer is valid only while `body` executes. In particular,
/// callers must not retain a pointer or use it to materialize a value for a
/// different existential or ABI representation. This is useful when one
/// synchronous operation needs several dynamically typed source values to
/// remain alive at once.
///
/// - Parameters:
///   - instances: Erased Swift values to project.
///   - body: Receives each value's dynamic type and initialized storage in
///     the same order as `instances`.
/// - Returns: The result of `body`.
public func withProjectedValues<Result>(
  of instances: [Any],
  _ body: ([(type: Any.Type, storage: UnsafeRawPointer)]) throws -> Result
) rethrows -> Result {
  var boxes = instances.map(container(for:))
  let values = boxes.indices.map { index in
    (
      type: boxes[index].metadata.type,
      storage: boxes[index].projectValue()
    )
  }
  return try body(values)
}

/// Asynchronously projects erased values' dynamic types and initialized
/// storage for the duration of `body`.
///
/// This has the same pointer-lifetime contract as ``withProjectedValues(of:_:)``
/// while preserving the projected containers across suspension points in
/// `body`.
///
/// - Parameters:
///   - instances: Erased Swift values to project.
///   - body: Receives each value's dynamic type and initialized storage in
///     the same order as `instances`.
/// - Returns: The result of `body`.
@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *)
public func withProjectedValues<Result>(
  of instances: [Any],
  _ body: ([(type: Any.Type, storage: UnsafeRawPointer)]) async throws -> Result
) async rethrows -> Result {
  var boxes = instances.map(container(for:))
  let values = boxes.indices.map { index in
    (
      type: boxes[index].metadata.type,
      storage: boxes[index].projectValue()
    )
  }
  return try await body(values)
}
