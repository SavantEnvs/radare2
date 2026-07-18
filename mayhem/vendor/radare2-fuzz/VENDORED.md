Vendored from https://github.com/radareorg/radare2-fuzz
commit 4b554a7da6749cbae43750aa5ec8fe5e051fabb1 (2025-11-30), for air-gapped/offline builds.

This is the OSS-Fuzz build.sh's companion repo: it clones this alongside radare2 and builds
every `targets/*.cc` against the static radare2 build (RADARE2_STATIC_BUILD). At the vendored
commit there is exactly ONE target (targets/ia_fuzz.cc) -- verified against the full upstream
git history (only 3 commits ever touched targets/, and targets/*.cc has always contained just
ia_fuzz.cc). mayhem/harnesses/ia_fuzz.cc is byte-identical to targets/ia_fuzz.cc here.

The seed corpus (targets/corpora/ia_fuzz_seed_corpus/, 854 files) is NOT duplicated here -- it is
already harvested byte-for-byte into mayhem/testsuite/ia_fuzz/.
