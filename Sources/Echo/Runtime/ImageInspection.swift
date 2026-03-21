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

#if os(Linux)
import CEcho
#endif

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
  #if os(Linux)
  iterateSharedObjects()
  #endif
  
  let protos = protocolLock.withLock {
    _protocols
  }
  
  return Array(unsafeUninitializedCapacity: protos.count) {
    for (i, proto) in protos.enumerated() {
      $0[i] = ProtocolDescriptor(ptr: proto)
    }
    
    $1 = protos.count
  }
}

let protocolLock = NSLock()
var _protocols = Set<UnsafeRawPointer>()

@_cdecl("registerProtocols")
func registerProtocols(section: UnsafeRawPointer, size: Int) {
  for i in 0 ..< size / 4 {
    let start = section.offset(of: i, as: Int32.self)
    let ptr = start.relativeDirectAddress(as: _ProtocolDescriptor.self)
    
    _ = protocolLock.withLock {
      _protocols.insert(ptr)
    }
  }
}

//===----------------------------------------------------------------------===//
// __swift5_proto/swift5_protocol_conformances
//===----------------------------------------------------------------------===//

let conformanceLock = NSLock()
var conformances = [UnsafeRawPointer: [ConformanceDescriptor]]()

@_cdecl("registerProtocolConformances")
func registerProtocolConformances(section: UnsafeRawPointer, size: Int) {
  for i in 0 ..< size / 4 {
    let start = section.offset(of: i, as: Int32.self)
    let ptr = start.relativeDirectAddress(as: _ConformanceDescriptor.self)
    let conformance = ConformanceDescriptor(ptr: ptr)
    
    #if canImport(ObjectiveC)
    if let objcClass = conformance.objcClass {
      conformanceLock.withLock {
        conformances[objcClass.ptr, default: []].append(conformance)
      }
      continue
    }
    #endif
    
    if let descriptor = conformance.contextDescriptor {
      conformanceLock.withLock {
        conformances[descriptor.ptr, default: []].append(conformance)
      }
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
  #if os(Linux)
  iterateSharedObjects()
  #endif

  return conformanceLock.withLock {
    for (_, confs) in conformances {
      for conf in confs {
        if conf.protocol == protocolDescriptor {
          return conf
        }
      }
    }
    return nil
  }
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
  #if os(Linux)
  iterateSharedObjects()
  #endif
  
  let types = typeLock.withLock {
    _types
  }
  
  var result = [ContextDescriptor]()
  result.reserveCapacity(types.count)
  
  for type in types {
    result.append(getContextDescriptor(at: type))
  }
  
  return result
}

let typeLock = NSLock()
var _types = Set<UnsafeRawPointer>()

@_cdecl("registerTypeMetadata")
func registerTypeMetadata(section: UnsafeRawPointer, size: Int) {
  for i in 0 ..< size / 4 {
    let start = section.offset(of: i, as: Int32.self)
    let ptr = start.relativeDirectAddress(as: _ContextDescriptor.self)
    
    _ = typeLock.withLock {
      _types.insert(ptr)
    }
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
func lookupSection(
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

#if os(Linux)

let sharedObjectLock = NSLock()
var sharedObjects = Set<String>()

@_cdecl("cacheSharedObject")
func cacheSharedObject(cString: UnsafePointer<CChar>) -> Bool {
  let str = String(cString: cString)
  
  let entry = sharedObjectLock.withLock {
    sharedObjects.insert(str)
  }
  
  return entry.inserted
}

#endif
