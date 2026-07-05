// mayhem/kat_blackformula.cpp — standalone Known-Answer-Test (KAT) bound to the SAME
// QuantLib::blackFormula entry point exercised by fuzz-test-suite/fuzzblackformula.cpp
// (the BlackFormulaFuzzer Mayhem target).
//
// Computes the Black-76 ATM call price for FIXED parameters and prints it. Analytic
// golden value (Black-76, ATM so forward == strike):
//   price = discount * F * (2*N(stdDev/2) - 1)
// with F=strike=100, stdDev=0.2, discount=1.0, displacement=0.0:
//   d1 = stdDev/2 = 0.1 ; N(0.1) = 0.5398278372770290
//   price = 100 * (2*0.5398278372770290 - 1) = 7.965567455405804...
// (independently verified with Python's math.erf-based normal CDF.) mayhem/test.sh
// checks the printed value against this golden answer within a small tolerance. Built
// by mayhem/build.sh against the SAME sanitized libQuantLib.so that the fuzz harnesses
// link -- if the sanitized pricing logic is neutered or broken, this prints the wrong
// (or no) value and test.sh's tolerance check fails (anti-reward-hacking, SPEC §6.3).
#include <ql/pricingengines/blackformula.hpp>
#include <cstdio>

int main() {
    using namespace QuantLib;
    Real price = blackFormula(Option::Call, /*strike=*/100.0, /*forward=*/100.0,
                               /*stdDev=*/0.2, /*discount=*/1.0, /*displacement=*/0.0);
    std::printf("KAT_BLACKFORMULA price=%.9f\n", (double)price);
    return 0;
}
