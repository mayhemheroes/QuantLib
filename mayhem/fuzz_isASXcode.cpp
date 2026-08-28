#include "ql/errors.hpp"
#include "ql/time/asx.hpp"
#include <climits>
#include <fuzzer/FuzzedDataProvider.h>
#include <stdint.h>
#include <stdio.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider provider(data, size);
    std::string str = provider.ConsumeRandomLengthString();

    try {
        QuantLib::ASX::isASXcode(str);
    } catch (QuantLib::Error e) {
    }

    return 0;
}
