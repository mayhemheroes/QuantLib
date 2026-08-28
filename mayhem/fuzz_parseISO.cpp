#include "ql/errors.hpp"
#include "ql/utilities/dataparsers.hpp"
#include <climits>
#include <fuzzer/FuzzedDataProvider.h>
#include <stdint.h>
#include <stdio.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider provider(data, size);
    std::string str = provider.ConsumeRandomLengthString();

    try {
        QuantLib::DateParser::parseISO(str);
    } catch (QuantLib::Error e) {
    } catch (std::invalid_argument e) {
    }

    return 0;
}
