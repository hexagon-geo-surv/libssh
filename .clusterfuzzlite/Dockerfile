FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y \
    cmake \
    zlib1g-dev \
    libssl-dev \
    libcmocka0 \
    libcmocka-dev \
    zip

RUN git clone --depth=1 https://github.com/google/oss-fuzz.git /tmp/oss-fuzz && \
    cp /tmp/oss-fuzz/projects/libssh/build.sh $SRC/build.sh && \
    cp /tmp/oss-fuzz/projects/libssh/project.yaml $SRC/project.yaml && \
    rm -rf /tmp/oss-fuzz

COPY . $SRC/libssh
WORKDIR $SRC/libssh