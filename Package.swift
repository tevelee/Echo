// swift-tools-version:5.10

import PackageDescription

let package = Package(
  name: "Echo",
  products: [
    .library(
      name: "Echo",
      targets: ["Echo"]
    )
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
    .testTarget(
      name: "EchoTests",
      dependencies: ["Echo"]
    )
  ]
)
