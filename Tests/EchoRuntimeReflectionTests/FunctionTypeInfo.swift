import EchoRuntimeReflection
import Testing

private enum ReflectedError: Error {
  case failed
}

private func hasType(_ type: Any.Type, matching expected: Any.Type) -> Bool {
  ObjectIdentifier(type) == ObjectIdentifier(expected)
}

private func isUnisolated(_ isolation: FunctionTypeInfo.Isolation) -> Bool {
  guard case .none = isolation else { return false }
  return true
}

private func zeroArgumentFunction() {}

private func variadicFunction(_ value: Int, _ rest: Int...) -> String {
  "\\(value):\\(rest.count)"
}

private func untypedThrowingFunction() throws {}

@available(macOS 15.0, *)
private func typedThrowingFunction(_ value: Int) async throws(ReflectedError) -> String {
  "\\(value)"
}

@Suite
struct FunctionTypeInfoTests {
  @Test
  func rejectsNonFunctionTypes() {
    #expect(FunctionTypeInfo(reflecting: Int.self) == nil)
  }

  @Test
  func reflectsZeroArgumentFunctionsWithoutRawMetadata() throws {
    let info = try #require(
      FunctionTypeInfo(reflecting: type(of: zeroArgumentFunction))
    )

    #expect(info.parameters.isEmpty)
    #expect(hasType(info.resultType, matching: Void.self))
    #expect(info.convention == .swift)
    #expect(info.effects.isAsync == false)
    #expect(info.effects.isThrowing == false)
    #expect(isUnisolated(info.effects.isolation))
  }

  @Test
  func reflectsParameterFactsWithoutRawMetadata() throws {
    let variadic = try #require(
      FunctionTypeInfo(reflecting: type(of: variadicFunction))
    )

    #expect(variadic.parameters.count == 2)
    #expect(hasType(variadic.parameters[0].type, matching: Int.self))
    #expect(variadic.parameters[0].ownership == .default)
    #expect(variadic.parameters[1].isVariadic)
    #expect(hasType(variadic.resultType, matching: String.self))

    let untypedThrowing = try #require(
      FunctionTypeInfo(reflecting: type(of: untypedThrowingFunction))
    )
    #expect(untypedThrowing.effects.isThrowing)
    #expect(untypedThrowing.effects.typedErrorType == nil)
  }

  @available(macOS 15.0, *)
  @Test
  func reflectsTypedThrowingEffectsWithoutRawMetadata() throws {
    let typedThrowing = try #require(
      FunctionTypeInfo(reflecting: type(of: typedThrowingFunction))
    )

    #expect(typedThrowing.effects.isAsync)
    #expect(typedThrowing.effects.isThrowing)
    #expect(
      typedThrowing.effects.typedErrorType.map {
        hasType($0, matching: ReflectedError.self)
      } == true
    )
    #expect(isUnisolated(typedThrowing.effects.isolation))
  }
}
