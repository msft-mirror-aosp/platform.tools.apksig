# Bazel (https://bazel.io/) BUILD file for apksig library and apksigner tool.

licenses(["notice"])  # Apache License 2.0

load("//tools/base/bazel:coverage.bzl", "coverage_java_test", "coverage_java_library")

# Public API of the apksig library
coverage_java_library(
    name = "apksig",
    srcs = glob(
        ["src/main/java/**/*.java"],
        exclude = ["src/main/java/com/android/apksig/internal/**/*.java"],
    ),
    visibility = ["//visibility:public"],
    deps = [":apksig-all"],
)

# All of apksig library, including private API which clients must not directly depend on. Private
# API may change without regard to its clients outside of the apksig project.
coverage_java_library(
    name = "apksig-all",
    srcs = glob(["src/main/java/**/*.java"]),
    visibility = [":apksig-private-api-clients"],
)

exports_files(
    ["LICENSE"],
    visibility = [":apksig-private-api-clients"],
)

# Packages which are permitted to depend on apksig-all target which offers private API in addition
# to the public API offered by the apksig target. The private API may change any time without
# regard to its clients outside of the apksig project.
package_group(
    name = "apksig-private-api-clients",
    packages = [
        # build-system:tools.apksig exports apksig as a self-contained JAR, containing public API
        # and all implementation details. It thus needs access to apksig-all.
        "//tools/base/build-system",
    ],
)

java_binary(
    name = "apksigner",
    srcs = glob([
        "src/apksigner/java/**/*.java",
    ]),
    main_class = "com.android.apksigner.ApkSignerTool",
    resources = glob([
        "src/apksigner/java/**/*.txt",
    ]),
    visibility = ["//visibility:public"],
    deps = [
        ":apksig",
        ":apksig-all",
        "//tools/base/bazel:langtools",
    ],
)

coverage_java_test(
    name = "all",
    srcs = glob([
        "src/test/java/com/android/apksig/**/*.java",
    ]),
    resources = glob([
        "src/test/resources/**/*",
    ]),
    test_class = "com.android.apksig.AllTests",
    deps = [
        ":apksig-all",
        "@maven//:junit.junit",
    ],
)
