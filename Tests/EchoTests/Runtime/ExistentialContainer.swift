import Foundation
import Testing
import Echo

private struct WheelContainer {
  let value: any Wheel
}

private struct DualWheelContainer {
  let value: any Wheel & DumbWheel
}

extension EchoTests {
  @Test
  func testExistentialContainer() throws {
    // NO WITNESS TABLE
    
    let x: Any = 128
    var xBox = container(for: x)
    let dataPtr = xBox.projectValue()
    
    #expect(typesEqual(xBox.type, Int.self))
    #expect(dataPtr.load(as: Int.self) == 128)
    
    // SINGLE WITNESS TABLE
    
    let y: any Wheel = CheeseWheel()
    var yBox = unsafeBitCast(WheelContainer(value: y), to: ExistentialContainer.self)
    let yPtr = yBox.base.projectValue()
    
    #expect(typesEqual(yBox.base.type, CheeseWheel.self))
    #expect(yPtr.load(as: CheeseWheel.self) == CheeseWheel())
    #expect(yBox.witnessTable.conformanceDescriptor.protocol.name == "Wheel")
    
    // DUAL WITNESS TABLE
    
    let z: any Wheel & DumbWheel = CheeseWheel()
    var zBox = unsafeBitCast(DualWheelContainer(value: z), to: DualExistentialContainer.self)
    let zPtr = zBox.base.projectValue()
    
    #expect(typesEqual(zBox.base.type, CheeseWheel.self))
    #expect(zPtr.load(as: CheeseWheel.self) == CheeseWheel())
    #expect(zBox.witnessTables.0.conformanceDescriptor.protocol.name == "DumbWheel")
    #expect(zBox.witnessTables.1.conformanceDescriptor.protocol.name == "Wheel")
    
    // Wrapped existentials
    
    func wrap<T>(_ x: T) -> Any {
      x
    }
    
    let wrapped = wrap(wrap(wrap(wrap(128))))
    var wrappedBox = container(for: wrapped)
    let wrappedPtr = wrappedBox.projectValue()
    #expect(typesEqual(wrappedBox.type, Int.self))
    #expect(wrappedPtr.load(as: Int.self) == 128)
  }
}
