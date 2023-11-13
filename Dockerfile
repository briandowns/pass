FROM alpine:3.16 AS builder

RUN apk update && apk upgrade && \
    apk add build-base           \
    make                         \
    gcc                          \
    libsodium-dev                \
    libsodium-static             \
    zlib-dev                     \
    zlib-static                  \
    libcurl                      \
    git                       && \
    rm -rf /var/lib/apt/lists/*

COPY . .

RUN make         && \
    make install && \
    make manpage

FROM alpine:3.18

RUN apk update && apk upgrade && \
    apk add mandoc            && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder bin/pass /usr/local/bin/pass
#COPY --from=builder /usr/local/man/man1/pass.1 /usr/local/man/man1/pass.1

ENTRYPOINT ["pass"]
