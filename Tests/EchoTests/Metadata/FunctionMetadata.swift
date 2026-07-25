import Foundation
import Testing
@testable import Echo

func add(_ x: Int, _ y: Int...) -> Int {
  fatalError()
}

extension EchoTests {
  @Test
  func testFunctionMetadata() throws {
    let metadata = try #require(reflect(add(_:_:)) as? FunctionMetadata)
    
    #expect(metadata.flags.numParams == 2)
    #expect(metadata.flags.convention == .swift)
    #expect(metadata.flags.throws == false)
    #expect(metadata.flags.hasParamFlags)
    #expect(metadata.flags.isEscaping)
    #expect(typeArraysEquals(metadata.paramTypes, [Int.self, Int.self]))
    #expect(typesEqual(metadata.resultType, Int.self))
    #expect(metadata.kind == .function)
    
    for (i, paramFlag) in metadata.paramFlags.enumerated() {
      switch i {
      case 0:
        #expect(paramFlag.bits == 0)
      case 1:
        #expect(paramFlag.bits == 128)
      default:
        fatalError()
      }
    }
    
    // VWT
    
    var extraInhabitantCount = 2147483647
    #if os(Linux)
    extraInhabitantCount = 4096
    #endif
    
    #expect(metadata.vwt.extraInhabitantCount == extraInhabitantCount)
    #expect(metadata.vwt.size == 16)
    #expect(metadata.vwt.stride == 16)
    #expect(metadata.vwt.flags.bits == 65543)
  }

  @Test
  func functionMetadataDecodesModernParameterAndDifferentiabilityFlags() {
    let storage = UnsafeMutableRawPointer.allocate(byteCount: 64, alignment: 8)
    storage.initializeMemory(as: UInt8.self, repeating: 0, count: 64)
    defer { storage.deallocate() }

    let flags = FunctionMetadata.Flags(bits: 0xA000001)
    storage.storeBytes(
      of: _FunctionMetadata(
        _kind: MetadataKind.function.rawValue,
        _flags: flags,
        _result: Int.self
      ),
      as: _FunctionMetadata.self
    )
    storage.storeBytes(of: Int.self, toByteOffset: 24, as: Any.Type.self)
    storage.storeBytes(of: UInt32(0xE03), toByteOffset: 32, as: UInt32.self)
    storage.storeBytes(of: UInt(2), toByteOffset: 40, as: UInt.self)

    let metadata = FunctionMetadata(ptr: UnsafeRawPointer(storage))
    let parameter = metadata.paramFlags[0]
    #expect(parameter.valueOwnership == .owned)
    #expect(parameter.ownership == .consuming)
    #expect(ParameterOwnership.borrowing == .shared)
    #expect(parameter.isNoDerivative)
    #expect(parameter.isIsolated)
    #expect(parameter.isSending)
    #expect(metadata.differentiabilityKind == .reverse)
  }

  @Test
  func invertibleProtocolSetsExposeKnownAndUnknownCapabilities() {
    let known = InvertibleProtocolSet(bits: 0x3)
    #expect(known.knownProtocols == [.copyable, .escapable])
    #expect(known.contains(.copyable))
    #expect(known.contains(.escapable))
    #expect(known.hasUnknownProtocols == false)

    let future = InvertibleProtocolSet(bits: 0x5)
    #expect(future.knownProtocols == [.copyable])
    #expect(future.unknownBits == 0x4)
    #expect(future.hasUnknownProtocols)
  }
}
