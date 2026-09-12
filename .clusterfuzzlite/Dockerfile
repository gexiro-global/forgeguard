# ClusterFuzzLite build environment. The base image already provides clang,
# libFuzzer and Atheris, which is why the fuzz harnesses are built here rather
# than in a plain GitHub runner: Atheris has no wheel for this platform and
# needs libFuzzer to build.
FROM gcr.io/oss-fuzz-base/base-builder-python

COPY . $SRC/versionsec
WORKDIR $SRC/versionsec
COPY .clusterfuzzlite/build.sh $SRC/build.sh
