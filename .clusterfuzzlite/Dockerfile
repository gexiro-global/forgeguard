# ClusterFuzzLite build environment. The base image already provides clang,
# libFuzzer and Atheris, which is why the fuzz harnesses are built here rather
# than in a plain GitHub runner: Atheris has no wheel for this platform and
# needs libFuzzer to build.
FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:6b2b3a7e4a2da50de47f94925cffbe34747e1aae4f33d7f07ba6c681dd648b23

COPY . $SRC/versionsec
WORKDIR $SRC/versionsec
COPY .clusterfuzzlite/build.sh $SRC/build.sh
