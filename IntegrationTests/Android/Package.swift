// swift-tools-version:5.10

import PackageDescription

let package = Package(
  name: "EchoAndroidIntegration",
  products: [
    .executable(
      name: "EchoAndroidSmoke",
      targets: ["EchoAndroidSmoke"]
    )
  ],
  dependencies: [
    .package(path: "../..")
  ],
  targets: [
    .executableTarget(
      name: "EchoAndroidSmoke",
      dependencies: [
        .product(name: "Echo", package: "Echo")
      ]
    )
  ]
)
