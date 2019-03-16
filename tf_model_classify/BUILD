# Description:
#   TensorFlow C++ inference example for labeling images.

#build function: use bazel build
#build gpu version code((-O) [-Wcpp]): bazel build -c opt --config=cuda tensorflow/examples/dl_classify_model/...
#build no gpu version code,going cd ~/tensorflow-1.1.0/, command: bazel build tensorflow/examples/dl_classify_model/...
#if error: going tensorflow source code dir: cd ~/tensorflow-1.1.0/, command: ./configure

package(default_visibility = ["//tensorflow:internal"])

licenses(["notice"])  # Apache 2.0

exports_files(["LICENSE"])

cc_binary(
    name = "dl_model_classify.so",
    srcs = [
        "dl_model_classify.h",
        "dl_model_classify.cc",
    ],
    linkopts = ["-lm -fpic -ldl"],
    linkshared = 1,
    deps = [
        "//tensorflow/cc:cc_ops",
        "//tensorflow/core:framework_internal",
        "//tensorflow/core:tensorflow",
    ],
)

filegroup(
    name = "all_files",
    srcs = glob(
        ["**/*"],
        exclude = [
            "**/METADATA",
            "**/OWNERS",
            "bin/**",
            "gen/**",
        ],
    ),
    visibility = ["//tensorflow:__subpackages__"],
)
