import Echo

protocol AndroidImageDiscoveryProtocol {}

struct AndroidImageDiscoveryConformer: AndroidImageDiscoveryProtocol {}

let probe: any AndroidImageDiscoveryProtocol = AndroidImageDiscoveryConformer()
print("Keeping conformance reachable: \(type(of: probe))")

guard
  let protocolDescriptor = Echo.protocols.first(where: {
    $0.name == "AndroidImageDiscoveryProtocol"
  })
else {
  fatalError("Echo did not discover the executable's protocol metadata.")
}

guard Echo.findConformance(to: protocolDescriptor) != nil else {
  fatalError("Echo did not discover the executable's protocol conformance metadata.")
}

guard
  Echo.types.contains(where: { descriptor in
    guard let descriptor = descriptor as? StructDescriptor else {
      return false
    }
    return descriptor.name == "AndroidImageDiscoveryConformer"
  })
else {
  fatalError("Echo did not discover the executable's type metadata.")
}

print("Echo Android ELF image discovery succeeded.")
