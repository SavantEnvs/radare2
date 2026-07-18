# syntax=docker/dockerfile:1.7
#
# Commit-image Dockerfile — builds ON TOP of the org C/C++ base image
# (ghcr.io/savantenvs/base). The base provides debian + clang/llvm + libFuzzer/afl++ + the
# identities + the build-contract ENV; this only adds the per-commit radare2 build.
#
# Build (from the repo root):
#   DOCKER_BUILDKIT=1 docker build -f mayhem/Dockerfile \
#       --build-arg COMMIT=$(git rev-parse HEAD) \
#       [--build-arg SOURCE_DATE_EPOCH=$(date +%s)] \
#       -t radare2-commit:test .

FROM ghcr.io/savantenvs/base:20260621

ARG COMMIT
ARG REPO_URL
# SOURCE_DATE_EPOCH stays an ARG (available to build.sh); never bake it as ENV — an empty value
# breaks clang. build.sh unsets it when empty.
ARG SOURCE_DATE_EPOCH

# Sanitizer override: the base exports SANITIZER_FLAGS (ASan+UBSan, halting) as the default.
# Declare it WITHOUT a default so an unset arg lets the base ENV flow through; --build-arg overrides.
ARG SANITIZER_FLAGS
ARG MAYHEM_JOBS=

# radare2 builds via its own ./configure + make (autotools) -- no meson needed. clang/llvm-ar/ld.lld
# and python3 (used to idempotently patch libr/Makefile for the ASan-static-build toolchain quirks;
# see mayhem/build.sh) all come from the base image already.

# Source enters from the build CONTEXT (the CI checkout): the FULL repo (incl. .git history)
# is copied to /mayhem as `mayhem`; build.sh builds in place.
# In-image cache for radare2's git subprojects (sdb/qjs/otezip/capstone-v5 ...; see step 1a of
# mayhem/build.sh). The first, online build mirrors each pinned revision there, and later builds
# clone from it. That covers the air-gapped re-run and the rebuild of a `git clean -ffdX`'ed tree,
# which deletes the gitignored subprojects/<name> checkouts. It is outside /mayhem so the clean
# leaves it alone, and it is owned by `mayhem` (2000), the identity build.sh runs as (SPEC 6.2 item 8, 6.5).
ENV R2_SUBPROJECTS_CACHE=/opt/toolchains/radare2-subprojects
USER root
RUN mkdir -p /opt/toolchains \
 && install -d -o 2000 -g 2000 -m 0755 /opt/toolchains/radare2-subprojects
USER mayhem

WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

RUN bash mayhem/build.sh

# Run radare2's functional tests at build time if test.sh exists
RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
