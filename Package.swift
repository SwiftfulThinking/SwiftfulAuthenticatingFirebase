// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SwiftfulAuthenticatingFirebase",
    platforms: [
        .iOS(.v17),
        .macOS(.v14)
    ],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "SwiftfulAuthenticatingFirebase",
            targets: ["SwiftfulAuthenticatingFirebase"]),
    ],
    dependencies: [
        // Here we add the dependency for the SendableDictionary package
//        .package(url: "https://github.com/SwiftfulThinking/SwiftfulAuthenticating.git", "0.0.0"..<"1.0.0"),
        .package(url: "https://github.com/SwiftfulThinking/SwiftfulAuthenticating.git", branch: "main"),
        .package(url: "https://github.com/firebase/firebase-ios-sdk.git", "11.0.0"..<"12.0.0"),
        .package(url: "https://github.com/SwiftfulThinking/SignInAppleAsync.git", branch: "main"),
        .package(url: "https://github.com/SwiftfulThinking/SignInGoogleAsync.git", branch: "main")
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "SwiftfulAuthenticatingFirebase",
            dependencies: [
                .product(name: "FirebaseAuth", package: "firebase-ios-sdk"),
                .product(name: "SwiftfulAuthenticating", package: "SwiftfulAuthenticating"),
                .product(name: "SignInAppleAsync", package: "SignInAppleAsync"),
                .product(name: "SignInGoogleAsync", package: "SignInGoogleAsync"),
            ]
        ),
        .testTarget(
            name: "SwiftfulAuthenticatingFirebaseTests",
            dependencies: ["SwiftfulAuthenticatingFirebase"]
        ),
    ]
)
