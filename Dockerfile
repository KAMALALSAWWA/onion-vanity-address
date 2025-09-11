FROM golang:latest AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 go build -v -trimpath -ldflags '-d -w -s'

FROM scratch
ARG REVISION
LABEL org.opencontainers.image.title="Fast Tor Onion Service vanity address generator"
LABEL org.opencontainers.image.description="This tool generates Tor Onion Service keypair with onion address that has a specified prefix"
LABEL org.opencontainers.image.authors="Alexander Yastrebov <yastrebov.alex@gmail.com>"
LABEL org.opencontainers.image.url="https://github.com/AlexanderYastrebov/onion-vanity-address"
LABEL org.opencontainers.image.licenses="BSD-3-Clause"
LABEL org.opencontainers.image.revision="${REVISION}"

COPY --from=builder /app/onion-vanity-address /onion-vanity-address

ENTRYPOINT ["/onion-vanity-address"]
