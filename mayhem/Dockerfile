FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential automake pkg-config libtool clang libboost-all-dev

COPY . /repo
WORKDIR /repo
RUN ./autogen.sh
RUN ./configure
WORKDIR /repo/ql/utilities
RUN make -j8
WORKDIR /repo/ql/time
RUN make -j8
WORKDIR /repo/ql/patterns
RUN make -j8

RUN clang++ /repo/mayhem/fuzz_parse.cpp -I /repo/ -fsanitize=fuzzer,address /repo/ql/errors.cpp  /repo/ql/time/.libs/libTime.a /repo/ql/utilities/.libs/libUtilities.a /repo/ql/time/.libs/libTime.a /repo/ql/utilities/.libs/libUtilities.a -o /fuzz
RUN clang++ /repo/mayhem/fuzz_parseISO.cpp -I /repo/ -fsanitize=fuzzer,address /repo/ql/errors.cpp  /repo/ql/time/.libs/libTime.a /repo/ql/utilities/.libs/libUtilities.a /repo/ql/time/.libs/libTime.a /repo/ql/utilities/.libs/libUtilities.a -o /fuzz2
RUN clang++ /repo/mayhem/fuzz_parseFormatted.cpp -I /repo/ -fsanitize=fuzzer,address /repo/ql/errors.cpp  /repo/ql/time/.libs/libTime.a /repo/ql/utilities/.libs/libUtilities.a /repo/ql/time/.libs/libTime.a /repo/ql/utilities/.libs/libUtilities.a -o /fuzz3
RUN clang++ /repo/mayhem/fuzz_isASXcode.cpp -I /repo/ -fsanitize=fuzzer,address /repo/ql/errors.cpp /repo/ql/settings.cpp /repo/ql/time/.libs/libTime.a /repo/ql/utilities/.libs/libUtilities.a /repo/ql/time/.libs/libTime.a /repo/ql/utilities/.libs/libUtilities.a /repo/ql/patterns/.libs/libPatterns.a -o /fuzz4
RUN clang++ /repo/mayhem/fuzz_isECBcode.cpp -I /repo/ -fsanitize=fuzzer,address /repo/ql/errors.cpp /repo/ql/settings.cpp /repo/ql/time/.libs/libTime.a /repo/ql/utilities/.libs/libUtilities.a /repo/ql/time/.libs/libTime.a /repo/ql/utilities/.libs/libUtilities.a /repo/ql/patterns/.libs/libPatterns.a -o /fuzz5

FROM ubuntu:22.04 as package

COPY --from=builder /fuzz /fuzz_parse
COPY --from=builder /fuzz2 /fuzz_parseISO
COPY --from=builder /fuzz3 /fuzz_parseFormatted
COPY --from=builder /fuzz4 /fuzz_isASXcode
COPY --from=builder /fuzz5 /fuzz_isECBcode

