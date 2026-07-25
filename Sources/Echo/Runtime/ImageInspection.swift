//
//  ImageInspection.swift
//  Echo
//
//  Created by Alejandro Alonso
//  Copyright © 2021 Alejandro Alonso. All rights reserved.
//

import Foundation

#if canImport(MachO)
import MachO
#elseif canImport(Glibc)
import Glibc
#endif

#if os(Linux) || os(Android)
import CEcho
#endif

func refreshLoadedImages() {
  #if os(Linux) || os(Android)
  iterateSharedObjects()
  #endif
}

//===----------------------------------------------------------------------===//
// __swift5_protos/swift5_protocols
//===----------------------------------------------------------------------===//

/// The list of all protocols this program has loaded.
///
/// NOTE: This list is populated once before the program starts with all of
///       the protocols that are statically know at compile time. If you
///       are attempting to load libraries dynamically at runtime, this list
///       will update automatically, so make sure if you need up to date
///       information on these protocols, fetch this often. Example:
///
///       var protocols = Echo.protocols
///       loadPlugin(...)
///       // protocols is now outdated! Refresh it by calling this again.
///       protocols = Echo.protocols
public var protocols: [ProtocolDescriptor] {
  refreshLoadedImages()
  
  let protos = imageInspectionStorage.protocols
  
  return Array(unsafeUninitializedCapacity: protos.count) {
    for (i, proto) in protos.enumerated() {
      $0[i] = ProtocolDescriptor(ptr: proto)
    }
    
    $1 = protos.count
  }
}

@_cdecl("registerProtocols")
public func registerProtocols(section: UnsafeRawPointer, size: Int) {
  for i in 0 ..< size / 4 {
    let start = section.offset(of: i, as: Int32.self)
    let ptr = start.relativeDirectAddress(as: _ProtocolDescriptor.self)
    
    imageInspectionStorage.insertProtocol(ptr)
  }
}

//===----------------------------------------------------------------------===//
// __swift5_proto/swift5_protocol_conformances
//===----------------------------------------------------------------------===//

@_cdecl("registerProtocolConformances")
public func registerProtocolConformances(section: UnsafeRawPointer, size: Int) {
  for i in 0 ..< size / 4 {
    let start = section.offset(of: i, as: Int32.self)
    let ptr = start.relativeDirectAddress(as: _ConformanceDescriptor.self)
    let conformance = ConformanceDescriptor(ptr: ptr)
    
    #if canImport(ObjectiveC)
    if let objcClass = conformance.objcClass {
      imageInspectionStorage.insert(conformance, for: objcClass.ptr)
      continue
    }
    #endif
    
    if let descriptor = conformance.contextDescriptor {
      imageInspectionStorage.insert(conformance, for: descriptor.ptr)
    }
  }
}

/// Finds a conformance descriptor for a given protocol by scanning all
/// registered conformances in the binary.
///
/// - Parameter protocolDescriptor: The protocol to find a conformance for.
/// - Returns: A conformance descriptor if any type in the binary conforms.
public func findConformance(
  to protocolDescriptor: ProtocolDescriptor
) -> ConformanceDescriptor? {
  refreshLoadedImages()

  return imageInspectionStorage.findConformance(to: protocolDescriptor)
}

/// Finds a conformance descriptor for a protocol with the given name.
///
/// - Parameter protocolName: The name of the protocol (e.g., "UserService").
/// - Returns: A conformance descriptor if found.
public func findConformance(toProtocolNamed protocolName: String) -> ConformanceDescriptor? {
  guard let proto = protocols.first(where: { $0.name == protocolName }) else {
    return nil
  }
  return findConformance(to: proto)
}

//===----------------------------------------------------------------------===//
// __swift5_types/swift5_type_metadata
//===----------------------------------------------------------------------===//

/// The list of all protocols this program has loaded.
///
/// NOTE: This list is populated once before the program starts with all of
///       the protocols that are statically know at compile time. If you
///       are attempting to load libraries dynamically at runtime, this list
///       will update automatically, so make sure if you need up to date
///       information on these protocols, fetch this often. Example:
///
///       var protocols = Echo.protocols
///       loadPlugin(...)
///       // protocols is now outdated! Refresh it by calling this again.
///       protocols = Echo.protocols
public var types: [ContextDescriptor] {
  refreshLoadedImages()
  
  let types = imageInspectionStorage.types
  
  var result = [ContextDescriptor]()
  result.reserveCapacity(types.count)
  
  for type in types {
    result.append(getContextDescriptor(at: type))
  }
  
  return result
}

@_cdecl("registerTypeMetadata")
public func registerTypeMetadata(section: UnsafeRawPointer, size: Int) {
  for i in 0 ..< size / 4 {
    let start = section.offset(of: i, as: Int32.self)

    // Each record is a RelativeDirectPointerIntPair<ContextDescriptor,
    // TypeReferenceKind>: the low 2 bits of the relative offset encode the
    // reference kind and must be masked off before resolving the pointer.
    // Records whose kind is an indirect reference point at a GOT slot that
    // holds the real descriptor, and ObjC class references never appear here.
    let raw = Int(start.load(as: Int32.self))
    let pointerOffset = raw & ~0x3

    // A zero offset is a null/padding record; skip it.
    guard pointerOffset != 0 else {
      continue
    }

    let addr = start + pointerOffset
    let ptr: UnsafeRawPointer

    switch TypeReferenceKind(rawValue: UInt16(raw & 0x3)) {
    case .directTypeDescriptor:
      ptr = addr
    case .indirectTypeDescriptor:
      ptr = addr.load(as: UnsafeRawPointer.self)
    default:
      // .directObjCClass / .indirectObjCClass are never emitted into this list.
      continue
    }

    imageInspectionStorage.insertType(ptr)
  }
}

//===----------------------------------------------------------------------===//
// Mach-O Image Inspection
//===----------------------------------------------------------------------===//

#if canImport(MachO)

#if arch(x86_64) || arch(arm64)
typealias mach_header_platform = mach_header_64
#else
typealias mach_header_platform = mach_header
#endif

@_cdecl("lookupSection")
public func lookupSection(
  _ header: UnsafePointer<mach_header>?,
  segment: UnsafePointer<CChar>?,
  section: UnsafePointer<CChar>?,
  do handler: @convention(c) (UnsafeRawPointer, Int) -> ()
) {
  guard let header = header else {
    return
  }
  
  var size: UInt = 0
  
  let section = header.withMemoryRebound(
    to: mach_header_platform.self,
    capacity: 1
  ) {
    getsectiondata($0, segment, section, &size)
  }
  
  guard section != nil else {
    return
  }
  
  handler(section!, Int(size))
}

#endif

//===----------------------------------------------------------------------===//
// ELF Image Inspection
//===----------------------------------------------------------------------===//

#if os(Linux) || os(Android)

@_cdecl("cacheSharedObject")
func cacheSharedObject(cString: UnsafePointer<CChar>) -> Bool {
  let str = String(cString: cString)
  let entry = imageInspectionStorage.insertSharedObject(str)
  
  return entry.inserted
}

#endif

/// Owns the process-wide image indexes used by the C and ELF callbacks.
///
/// Every mutable collection is accessed while holding its corresponding lock.
/// The callbacks may arrive from arbitrary loader threads, so this reference
/// type is explicitly marked `@unchecked Sendable` after establishing that
/// synchronization boundary.
final class ImageInspectionStorage: @unchecked Sendable {
  private let protocolLock = NSLock()
  private var storedProtocols = Set<UnsafeRawPointer>()

  private let conformanceLock = NSLock()
  private var storedConformances = [UnsafeRawPointer: [ConformanceDescriptor]]()

  private let typeLock = NSLock()
  private var storedTypes = Set<UnsafeRawPointer>()

  private let sharedObjectLock = NSLock()
  private var storedSharedObjects = Set<String>()

  var protocols: Set<UnsafeRawPointer> {
    protocolLock.withLock { storedProtocols }
  }

  var types: Set<UnsafeRawPointer> {
    typeLock.withLock { storedTypes }
  }

  func insertProtocol(_ pointer: UnsafeRawPointer) {
    _ = protocolLock.withLock {
      storedProtocols.insert(pointer)
    }
  }

  func insert(_ conformance: ConformanceDescriptor, for key: UnsafeRawPointer) {
    conformanceLock.withLock {
      storedConformances[key, default: []].append(conformance)
    }
  }

  func conformances(for key: UnsafeRawPointer) -> [ConformanceDescriptor] {
    conformanceLock.withLock {
      storedConformances[key, default: []]
    }
  }

  func findConformance(
    to protocolDescriptor: ProtocolDescriptor
  ) -> ConformanceDescriptor? {
    conformanceLock.withLock {
      for conformances in storedConformances.values {
        if let conformance = conformances.first(where: { $0.protocol == protocolDescriptor }) {
          return conformance
        }
      }
      return nil
    }
  }

  func insertType(_ pointer: UnsafeRawPointer) {
    _ = typeLock.withLock {
      storedTypes.insert(pointer)
    }
  }

  func insertSharedObject(_ path: String) -> (inserted: Bool, memberAfterInsert: String) {
    sharedObjectLock.withLock {
      storedSharedObjects.insert(path)
    }
  }
}

let imageInspectionStorage = ImageInspectionStorage()
