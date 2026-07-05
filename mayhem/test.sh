#!/usr/bin/env bash
#
# quantlib/mayhem/test.sh — functional oracle for the QuantLib integration.
#
# PRIMARY oracle: two standalone Known-Answer-Tests (KATs), built by mayhem/build.sh as
# /mayhem/kat_dateparser and /mayhem/kat_blackformula. Each is a tiny standalone program
# (NOT a fuzz harness) that calls the SAME QuantLib entry point its corresponding fuzz
# target exercises, with a FIXED input, and prints a value:
#   - kat_dateparser:    DateParser::parseISO("2026-07-04") -> year=2026 month=7 day=4
#                         (same API as fuzz-test-suite/dateparserfuzzer.cpp / DateParserFuzzer)
#   - kat_blackformula:  blackFormula(Call, strike=100, forward=100, stdDev=0.2,
#                         discount=1.0, displacement=0.0) -> 7.965567455405804... (Black-76
#                         ATM call; analytic golden value independently verified in Python)
#                         (same API as fuzz-test-suite/fuzzblackformula.cpp / BlackFormulaFuzzer)
# Both KATs are linked (by build.sh) against the SAME sanitized libQuantLib.so the fuzz
# harnesses use. This is a REAL functional assertion, not "the binary exited 0": if the
# sanitized QuantLib logic these fuzz targets exercise is neutered or broken, the printed
# value changes (or the KAT prints nothing at all, e.g. if the process is killed before
# printing) and the checks below FAIL. This is what makes the oracle non-reward-hackable
# per SPEC §6.3 — it is bound to the actual fuzzed code, unlike "did the test-suite pass"
# (a separate binary the fuzz targets don't touch).
#
# SECONDARY signal (best-effort): QuantLib's own quantlib-test-suite, if build.sh built one.
# Its assertion counts are folded into the same CTRF summary but are not required for the
# oracle to be behavioral -- the two KATs above already guarantee that.
set -uo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

PASSED=0
FAILED=0

# ── KAT 1: DateParserFuzzer's QuantLib::DateParser::parseISO ────────────────────────────
KAT1=""
for loc in "$SRC/mayhem/kat_dateparser" /mayhem/kat_dateparser; do
  [ -x "$loc" ] && { KAT1="$loc"; break; }
done
if [ -z "$KAT1" ]; then
  echo "ERROR: kat_dateparser binary not found (build.sh should have built it)" >&2
  FAILED=$((FAILED+1))
else
  out1=$("$KAT1" 2>&1 || true)
  echo "=== kat_dateparser: $out1"
  if [ "$out1" = "KAT_DATEPARSER year=2026 month=7 day=4" ]; then
    PASSED=$((PASSED+1))
  else
    echo "FAIL: kat_dateparser expected 'KAT_DATEPARSER year=2026 month=7 day=4', got: '$out1'" >&2
    FAILED=$((FAILED+1))
  fi
fi

# ── KAT 2: BlackFormulaFuzzer's QuantLib::blackFormula (Black-76 ATM call) ───────────────
KAT2=""
for loc in "$SRC/mayhem/kat_blackformula" /mayhem/kat_blackformula; do
  [ -x "$loc" ] && { KAT2="$loc"; break; }
done
if [ -z "$KAT2" ]; then
  echo "ERROR: kat_blackformula binary not found (build.sh should have built it)" >&2
  FAILED=$((FAILED+1))
else
  out2=$("$KAT2" 2>&1 || true)
  echo "=== kat_blackformula: $out2"
  price="$(printf '%s' "$out2" | sed -n 's/^KAT_BLACKFORMULA price=\(.*\)$/\1/p')"
  if [ -n "$price" ] && awk -v p="$price" 'BEGIN{ e=7.965567455405804; d=p-e; if (d<0) d=-d; exit !(d<1e-6) }'; then
    PASSED=$((PASSED+1))
  else
    echo "FAIL: kat_blackformula expected price~=7.965567455405804 (+/-1e-6), got: '$out2'" >&2
    FAILED=$((FAILED+1))
  fi
fi

# ── Secondary signal (best-effort): QuantLib's own test suite, if present ───────────────
TESTSUITE_BIN=""
for loc in "$SRC/build/test-suite/quantlib-test-suite" /mayhem/build/test-suite/quantlib-test-suite /mayhem/quantlib-test-suite; do
  if [ -x "$loc" ]; then
    TESTSUITE_BIN="$loc"
    break
  fi
done

if [ -n "$TESTSUITE_BIN" ]; then
  echo "=== Running QuantLib test suite from $TESTSUITE_BIN (secondary signal) ==="
  out=$("$TESTSUITE_BIN" 2>&1 || true)
  rc=$?
  echo "$out" | tail -20

  TS_PASSED=0
  TS_FAILED=0
  if echo "$out" | grep -q "passed with"; then
    TS_PASSED=$(echo "$out" | grep "passed with" | sed -n 's/.*with: \([0-9]*\) assertions.*/\1/p' | tail -1)
    TS_PASSED="${TS_PASSED:-0}"
  fi
  if echo "$out" | grep -q "errors in.*test suite"; then
    TS_FAILED=$(echo "$out" | grep "errors in.*test suite" | sed -n 's/^\*\*\* \([0-9]*\) errors.*/\1/p' | tail -1)
    TS_FAILED="${TS_FAILED:-0}"
  fi
  if [ "$rc" -ne 0 ] && [ "$TS_FAILED" -eq 0 ] && [ "$TS_PASSED" -eq 0 ]; then
    TS_FAILED=1
  fi
  PASSED=$((PASSED+TS_PASSED))
  FAILED=$((FAILED+TS_FAILED))
else
  echo "NOTE: quantlib-test-suite binary not found; relying on the two KATs above only" >&2
fi

emit_ctrf "quantlib-kat+test" "$PASSED" "$FAILED" 0
