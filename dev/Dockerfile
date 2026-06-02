# Build environment for focus-sched. Compiles the BPF object, skeleton and
# loader; it does not run them (that needs a sched_ext kernel, see dev/vm-test.sh).
#
#   docker build -t focus-sched-dev dev
#   docker run --rm -v "$PWD":/src -w /src/scheduler focus-sched-dev make
FROM debian:trixie

RUN apt-get update && apt-get install -y --no-install-recommends \
        clang llvm make git ca-certificates pkg-config \
        libbpf-dev bpftool libelf-dev zlib1g-dev gcc libc6-dev \
        python3 \
    && rm -rf /var/lib/apt/lists/*
