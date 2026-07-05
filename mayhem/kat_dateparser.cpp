// mayhem/kat_dateparser.cpp — standalone Known-Answer-Test (KAT) bound to the SAME
// QuantLib::DateParser API exercised by fuzz-test-suite/dateparserfuzzer.cpp
// (the DateParserFuzzer Mayhem target).
//
// Parses a FIXED ISO date string with QuantLib::DateParser::parseISO and prints the
// resulting (year, month, day). mayhem/test.sh checks this output against the known-
// correct answer (2026-07-04 -> year=2026 month=7 day=4). Built by mayhem/build.sh
// against the SAME sanitized libQuantLib.so that the fuzz harnesses link -- if the
// sanitized DateParser logic is neutered or broken, this prints the wrong (or no)
// fields and test.sh's exact-match check fails (anti-reward-hacking, SPEC §6.3).
#include <ql/utilities/dataparsers.hpp>
#include <ql/time/date.hpp>
#include <cstdio>

int main() {
    using namespace QuantLib;
    Date d = DateParser::parseISO("2026-07-04");
    std::printf("KAT_DATEPARSER year=%d month=%d day=%d\n",
                (int)d.year(), (int)d.month(), (int)d.dayOfMonth());
    return 0;
}
