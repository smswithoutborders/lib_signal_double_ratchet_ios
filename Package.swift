import PackageDescription
let package = Package(
    name: "MyStaticLib",
    products: [
        .library(name: "SWOB-SignalDoubleRatchet-ios", targets: ["smswithoutborders_libsig_doubleratchet"])
    ],
    targets: [
        .target(name: "smswithoutborders_libsig_doubleratchet", path: "smswithoutborders_libsig_doubleratchet")
    ]
)
