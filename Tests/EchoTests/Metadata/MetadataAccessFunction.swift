import Foundation
import Testing
import Echo

struct FooBar0 {}
struct FooBar1<T> {}
struct FooBar2<T, U> {}
struct FooBar3<T, U, V> {}
struct FooBar4<T, U, V, W> {}

struct FooBaz1<T: Equatable> {}
struct FooBaz2<T: Equatable, U: Equatable> {}
struct FooBaz3<T: Equatable, U: Equatable, V: Equatable> {}
struct FooBaz4<T: Equatable, U: Equatable, V: Equatable, W: Equatable> {}

private struct AccessorPackFixture<each Element> {}

enum MetadataAccessFunctionTests {
  static func testPlain() throws {
    // 0 ARG
    
    let metadata0 = reflectStruct(FooBar0.self)!
    let accessor0 = metadata0.descriptor.accessor
    let response0 = accessor0(.complete)
    #expect(response0.state == .complete)
    #expect(typesEqual(response0.type, FooBar0.self))
    
    // 1 ARG
    
    let metadata1 = reflectStruct(FooBar1<Int>.self)!
    let accessor1 = metadata1.descriptor.accessor
    let response1 = accessor1(.complete, Double.self)
    #expect(response1.state == .complete)
    #expect(typesEqual(response1.type, FooBar1<Double>.self))
    
    // 2 ARG
    
    let metadata2 = reflectStruct(FooBar2<Int, Int>.self)!
    let accessor2 = metadata2.descriptor.accessor
    let response2 = accessor2(.complete, Double.self, Double.self)
    #expect(response2.state == .complete)
    #expect(typesEqual(response2.type, FooBar2<Double, Double>.self))
    
    // 3 ARG
    
    let metadata3 = reflectStruct(FooBar3<Int, Int, Int>.self)!
    let accessor3 = metadata3.descriptor.accessor
    let response3 = accessor3(.complete, Double.self, Double.self, Double.self)
    #expect(response3.state == .complete)
    #expect(typesEqual(response3.type, FooBar3<Double, Double, Double>.self))
    
    // 4 ARG
    
    let metadata4 = reflectStruct(FooBar4<Int, Int, Int, Int>.self)!
    let accessor4 = metadata4.descriptor.accessor
    let response4 = accessor4(.complete, Double.self, Double.self, Double.self, Double.self)
    #expect(response4.state == .complete)
    #expect(typesEqual(response4.type, FooBar4<Double, Double, Double, Double>.self))
  }
  
  static func testWitnessTable() throws {
    let equatableMetadata = reflect(_typeByName("SQ")!) as! ExistentialMetadata
    let equatable = equatableMetadata.protocols[0]
    var doubleEquatable: WitnessTable? = nil
    
    let hashableMetadata = reflect(_typeByName("SH")!) as! ExistentialMetadata
    let hashable = hashableMetadata.protocols[0]
    var doubleHashable: WitnessTable? = nil
    
    for conformance in reflectStruct(Double.self)!.conformances {
      if conformance.protocol == equatable {
        #expect(conformance.flags.hasGenericWitnessTable == false)
        doubleEquatable = conformance.witnessTablePattern
      }
      
      if conformance.protocol == hashable {
        #expect(conformance.flags.hasGenericWitnessTable == false)
        doubleHashable = conformance.witnessTablePattern
      }
    }
    
    let typeWitness = (Double.self, doubleEquatable)
    let typeWitness1 = (Double.self, doubleHashable)
    
    // 1 ARG
    
    let metadata1 = reflectStruct(FooBaz1<Int>.self)!
    let accessor1 = metadata1.descriptor.accessor
    let response1 = accessor1(.complete, typeWitness)
    #expect(response1.state == .complete)
    #expect(typesEqual(response1.type, FooBaz1<Double>.self))
    
    // 2 ARG
    
    let metadata2 = reflectStruct(FooBaz2<Int, Int>.self)!
    let accessor2 = metadata2.descriptor.accessor
    let response2 = accessor2(.complete, typeWitness, typeWitness)
    #expect(response2.state == .complete)
    #expect(typesEqual(response2.type, FooBaz2<Double, Double>.self))
    
    // 3 ARG
    
    let metadata3 = reflectStruct(FooBaz3<Int, Int, Int>.self)!
    let accessor3 = metadata3.descriptor.accessor
    let response3 = accessor3(.complete, typeWitness, typeWitness, typeWitness)
    #expect(response3.state == .complete)
    #expect(typesEqual(response3.type, FooBaz3<Double, Double, Double>.self))
    
    // 4 ARG
    
    let metadata4 = reflectStruct(FooBaz4<Int, Int, Int, Int>.self)!
    let accessor4 = metadata4.descriptor.accessor
    let response4 = accessor4(.complete, typeWitness, typeWitness, typeWitness, typeWitness)
    #expect(response4.state == .complete)
    #expect(typesEqual(response4.type, FooBaz4<Double, Double, Double, Double>.self))
    
    // STDLIB TYPES
    
    let dictMetadata = reflectStruct([Int: Int].self)!
    let dictAccessor = dictMetadata.descriptor.accessor
    // The last argument has a nil witness table because the value type in
    // dictionary has no conformance requirements.
    let dictResponse = dictAccessor(.complete, typeWitness1, (Double.self, nil))
    #expect(dictResponse.state == .complete)
    #expect(typesEqual(dictResponse.type, [Double: Double].self))
  }

  static func testWitnessTableDistinctArgs() throws {
    // Regression: createMetadataAccessBuffer previously stored args[0] for
    // every key-argument slot, so any instantiation whose generic arguments
    // differ by position came out wrong. The bug only surfaces when (a) the
    // arguments are distinct and (b) witness tables are present, which forces
    // the buffer path instead of the fixed-arity accessors. FooBaz2<Int, _>
    // with two Equatable witness tables hits exactly that path.
    let equatableMetadata = reflect(_typeByName("SQ")!) as! ExistentialMetadata
    let equatable = equatableMetadata.protocols[0]

    func equatableWitness(for type: Any.Type) -> WitnessTable {
      for conformance in reflectStruct(type)!.conformances
      where conformance.protocol == equatable {
        return conformance.witnessTablePattern
      }
      fatalError("\(type) has no Equatable conformance")
    }

    let intEquatable = equatableWitness(for: Int.self)
    let doubleEquatable = equatableWitness(for: Double.self)

    let metadata = reflectStruct(FooBaz2<Int, Int>.self)!
    let accessor = metadata.descriptor.accessor
    let response = accessor(
      .complete,
      (Int.self, intEquatable),
      (Double.self, doubleEquatable)
    )
    #expect(response.state == .complete)
    #expect(typesEqual(response.type, FooBaz2<Int, Double>.self))
  }

  static func testTypedGenericArguments() throws {
    let plain = try #require(reflectStruct(FooBar1<Int>.self))
    let plainResponse = plain.descriptor.accessor(
      .complete,
      genericArguments: [.metadata(Double.self)]
    )
    #expect(typesEqual(plainResponse.type, FooBar1<Double>.self))

    let constrained = try #require(reflectStruct(FooBaz1<Double>.self))
    let constrainedArguments = constrained.genericArguments
    #expect(constrainedArguments.count == 2)
    guard case .metadata = constrainedArguments[0],
          case .witnessTable = constrainedArguments[1]
    else {
      Issue.record("Expected metadata followed by a witness-table argument.")
      return
    }

    let accessor = try #require(reflectStruct(FooBaz1<Int>.self)?.descriptor.accessor)
    let constrainedResponse = accessor(.complete, genericArguments: constrainedArguments)
    #expect(typesEqual(constrainedResponse.type, FooBaz1<Double>.self))

    let pack = try #require(reflectStruct(AccessorPackFixture<Int, String, Bool>.self))
    let packResponse = pack.descriptor.accessor(
      .complete,
      genericArguments: pack.genericArguments
    )
    #expect(typesEqual(packResponse.type, AccessorPackFixture<Int, String, Bool>.self))
  }
}

extension EchoTests {
  @Test
  func testMetadataAccessFunction() throws {
    try MetadataAccessFunctionTests.testPlain()
    try MetadataAccessFunctionTests.testWitnessTable()
    try MetadataAccessFunctionTests.testWitnessTableDistinctArgs()
    try MetadataAccessFunctionTests.testTypedGenericArguments()
  }
}
