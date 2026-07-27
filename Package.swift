// swift-tools-version:6.0

import PackageDescription

let package = Package(
  name: "Echo",
  products: [
    .library(
      name: "Echo",
      targets: ["Echo"]
    ),
    .library(
      name: "EchoRuntimeReflection",
      targets: ["EchoRuntimeReflection"]
    ),
    .library(
      name: "EchoRuntimeSupport",
      targets: ["EchoRuntimeSupport"]
    ),
  ],
  dependencies: [
    .package(url: "https://github.com/apple/swift-atomics.git", from: "1.3.1")
  ],
  targets: [
    .target(
      name: "CEcho",
      dependencies: []
    ),
    .target(
      name: "Echo",
      dependencies: [
        "CEcho",
        .product(name: "Atomics", package: "swift-atomics"),
      ]
    ),
    .target(
      name: "EchoRuntimeReflection",
      dependencies: ["Echo"]
    ),
    .target(
      name: "EchoRuntimeSupport",
      dependencies: ["Echo"]
    ),
    .testTarget(
      name: "EchoTests",
      dependencies: ["Echo"]
    ),
    .testTarget(
      name: "EchoRuntimeReflectionTests",
      dependencies: ["EchoRuntimeReflection"]
    ),
    .testTarget(
      name: "EchoRuntimeSupportTests",
      dependencies: ["EchoRuntimeSupport"]
    ),
  ],
  swiftLanguageModes: [.v6]
)
