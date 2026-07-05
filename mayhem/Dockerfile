# syntax=docker/dockerfile:1.7
#
# Commit-image Dockerfile — builds ON TOP of the org C/C++ base image
# (ghcr.io/mayhemheroes/base). The base provides debian + clang/llvm + libFuzzer/afl++ + the
# identities + the build-contract ENV; this only adds the per-commit quantlib build.
#
# Build (from the repo root):
#   DOCKER_BUILDKIT=1 docker build -f mayhem/Dockerfile \
#       --build-arg COMMIT=$(git rev-parse HEAD) \
#       [--build-arg SOURCE_DATE_EPOCH=$(date +%s)] \
#       -t quantlib-commit:test .

FROM ghcr.io/mayhemheroes/base:20260621

ARG COMMIT
ARG REPO_URL
# SOURCE_DATE_EPOCH stays an ARG (available to build.sh); never bake it as ENV — an empty value
# breaks clang. build.sh unsets it when empty.
ARG SOURCE_DATE_EPOCH

# Sanitizer override: the base exports SANITIZER_FLAGS (ASan+UBSan, halting) as the default.
# Declare it WITHOUT a default so an unset arg lets the base ENV flow through; --build-arg overrides.
ARG SANITIZER_FLAGS
ARG MAYHEM_JOBS=

# QuantLib builds with cmake/ninja and requires Boost headers.
# Pre-cache the Boost tarball at a fixed location for air-gapped re-run.
USER root
RUN [ -n "$SOURCE_DATE_EPOCH" ] && repro-sources-list.sh || true; \
    apt-get update && apt-get install -yq --no-install-recommends \
      cmake ninja-build \
    && rm -rf /var/lib/apt/lists/*

# Pre-fetch and cache Boost 1.87.0 (pinned version, matches OSS-Fuzz).
# Build it as root so mayhem can use the installed headers at /usr/include and libs at /usr/lib.
RUN cd /tmp && \
    wget -q https://archives.boost.io/release/1.87.0/source/boost_1_87_0.tar.bz2 && \
    tar -xjf boost_1_87_0.tar.bz2 && \
    cd boost_1_87_0 && \
    CFLAGS="" CXXFLAGS="" ./bootstrap.sh > /dev/null 2>&1 && \
    CFLAGS="" CXXFLAGS="" ./b2 headers > /dev/null 2>&1 && \
    ./b2 --with-math install > /dev/null 2>&1 || true && \
    echo "Boost 1.87.0 headers installed to /usr/local/include" && \
    rm -rf /tmp/boost_1_87_0 /tmp/boost_1_87_0.tar.bz2

USER mayhem

# Source enters from the build CONTEXT (the CI checkout): the FULL repo (incl. .git history)
# is copied to /mayhem as `mayhem`; build.sh builds in place.
WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

RUN bash mayhem/build.sh

# Run QuantLib's functional test suite at build time (a failing suite fails the image build).
RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
