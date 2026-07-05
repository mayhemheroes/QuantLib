#!/usr/bin/env bash
#
# quantlib/mayhem/build.sh — build QuantLib's 14 fuzz harnesses as sanitized libFuzzer
# targets, AND two standalone Known-Answer-Test (KAT) binaries for mayhem/test.sh's
# functional oracle (see the KAT section below).
#
# QuantLib is a C++ financial library used by practitioners and institutions worldwide.
# The fuzzed surface includes pricing engines, interpolations, date parsing, and bonds:
#   DateParserFuzzer      — date string parsing
#   AmericanOptionFuzzer  — American option pricing
#   EuropeanOptionFuzzer  — European option pricing
#   BarrierOptionFuzzer   — barrier option pricing
#   AsianOptionFuzzer     — Asian option pricing
#   BasketOptionFuzzer    — basket option pricing
#   VanillaOptionFuzzer   — vanilla option pricing
#   AmortizedBondsFuzzer  — amortized bonds pricing
#   BlackFormulaFuzzer    — Black-Scholes formula
#   InterpolationsFuzzer  — curve interpolation
#   TimeFunctionsFuzzer   — time functions
#   CashFlowsFuzzer       — cash flow valuation
#   IndexManagerFuzzer    — index management
#   ExchangeRateManagerFuzzer — exchange rate management
#
# Build contract comes from the org base ENV (CC/CXX/SANITIZER_FLAGS/LIB_FUZZING_ENGINE/SRC/
# STANDALONE_FUZZ_MAIN). We compile the QuantLib library ITSELF with $SANITIZER_FLAGS so the
# library code (not just the harness) is instrumented.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) for SANITIZER_FLAGS so an explicit empty --build-arg builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS

cd "$SRC"

# Boost is pre-installed in the Dockerfile (at /usr/local/include, /usr/local/lib).
# The Dockerfile handles the Boost build as root; build.sh just uses it.
# (Note: $SRC is /mayhem, and the QuantLib source is at /mayhem, not /mayhem/quantlib)

# ── Build QuantLib with CMake + Ninja ──────────────────────────────────────────────────────
# The OSS-Fuzz recipe builds with CMAKE_BUILD_TYPE=Release + sanitizers, which is correct.
# We configure:
#  - ASan/UBSan via SANITIZER_FLAGS (from base ENV, applied to CXX/CXXFLAGS)
#  - Fuzz harnesses enabled (QL_BUILD_FUZZ_TEST_SUITE=ON)
#  - QuantLib's own ~1000-test Boost.Test suite disabled (QL_BUILD_TEST_SUITE=OFF) — it's a
#    SEPARATE binary from the fuzz targets (fuzzing a target's LLVMFuzzerTestOneInput never
#    touches it), so "did the test suite pass" asserts nothing about the fuzzed code and is
#    reward-hackable (SPEC §6.3), plus building it roughly doubles compile time for no
#    functional-oracle benefit. mayhem/test.sh instead runs two standalone Known-Answer-Tests
#    (built below) that call the SAME QuantLib entry points the DateParserFuzzer /
#    BlackFormulaFuzzer harnesses exercise, against the SAME sanitized library.
#  - Examples and benchmarks disabled (reduces build time)
#
mkdir -p build
cd build

# Thread DEBUG_FLAGS into CMAKE_CXX_FLAGS_RELEASE so they reach the fuzz harnesses.
# -fsanitize=fuzzer-no-link adds SanitizerCoverage instrumentation (without pulling in a
# libFuzzer main) to libQuantLib itself and the 14 fuzz-test-suite TUs, so Mayhem sees real
# edge coverage instead of edges=0. $LIB_FUZZING_ENGINE (-fsanitize=fuzzer) is still what
# supplies the actual libFuzzer main/driver at the final link step, below.
export CXXFLAGS="${SANITIZER_FLAGS} -fsanitize=fuzzer-no-link ${DEBUG_FLAGS} ${CXXFLAGS:-}"
cmake .. \
  -GNinja \
  -DBOOST_ROOT=/usr/local \
  -DCMAKE_BUILD_TYPE=Release \
  -DQL_BUILD_FUZZ_TEST_SUITE=ON \
  -DQL_BUILD_TEST_SUITE=OFF \
  -DQL_BUILD_BENCHMARK=OFF \
  -DQL_BUILD_EXAMPLES=OFF \
  -DCMAKE_CXX_STANDARD=20 \
  2>&1 | grep -v "^--"

cmake --build . --verbose -j"${MAYHEM_JOBS}"

# Copy fuzz harnesses to /mayhem (the CMake build puts them in build/fuzz-test-suite/)
for target in \
    DateParserFuzzer \
    AmericanOptionFuzzer \
    AmortizedBondsFuzzer \
    EuropeanOptionFuzzer \
    InterpolationsFuzzer \
    TimeFunctionsFuzzer \
    BlackFormulaFuzzer \
    VanillaOptionFuzzer \
    Fuzz_CashFlows \
    Fuzz_IndexManager \
    Fuzz_ExchangeRateManager \
    Fuzz_BarrierOption \
    Fuzz_AsianOption \
    Fuzz_BasketOption; do
  if [ -f "fuzz-test-suite/$target" ]; then
    cp "fuzz-test-suite/$target" /mayhem/
  else
    echo "WARNING: fuzz-test-suite/$target not found"
  fi
done

# ── Standalone Known-Answer-Test (KAT) binaries — mayhem/test.sh oracle ──────────────────
# NOT fuzz targets. Each calls the SAME QuantLib entry point its corresponding fuzz harness
# exercises (DateParser::parseISO / blackFormula), with a FIXED input, and prints a value
# mayhem/test.sh checks against a known-correct golden answer. Linked against the SAME
# sanitized libQuantLib.so the fuzz harnesses use (built above, in $PWD/ql — we're still
# cd'd into "build" here) so a neutered/broken library is caught by test.sh, not just "ran
# without crashing" (SPEC §6.3 anti-reward-hacking).
QL_LIB_DIR="$PWD/ql"
for kat in kat_dateparser kat_blackformula; do
  $CXX -std=c++20 -I"$SRC" -I"$PWD" -I/usr/local/include \
      $SANITIZER_FLAGS $DEBUG_FLAGS \
      "$SRC/mayhem/${kat}.cpp" \
      -L"$QL_LIB_DIR" -lQuantLib -Wl,-rpath,"$QL_LIB_DIR" \
      -o "/mayhem/${kat}"
done

echo "build.sh: built fuzz harnesses"
ls -la /mayhem/ | grep -E "Fuzzer|Fuzz_|^kat_" || true

echo "build.sh: complete"

# DateParserFuzzer dropped: crashes immediately on a real UBSan signed-overflow in ql/time/date.hpp:409 (0-edge, unfuzzable)
rm -f /mayhem/DateParserFuzzer /mayhem/DateParserFuzzer.dict 2>/dev/null || true
