FROM alpine:3.16

RUN apk update && apk upgrade && \
    apk add build-base \
    make \
    gcc \
    libsodium-dev \
    libsodium-static \
    git && \
    rm -rf /var/lib/apt/lists/*

COPY . .

RUN make && \
    make install

ENTRYPOINT ["sh"]
