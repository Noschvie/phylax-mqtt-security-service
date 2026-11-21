# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Multi-stage build (design section 7.7): Go build stage, Debian slim runtime.
# The build stage runs on the build platform and cross-compiles, so a
# multi-arch build (linux/amd64, linux/arm64) needs emulation only for the
# runtime stage.

FROM --platform=$BUILDPLATFORM golang:1.27-trixie AS build
WORKDIR /src
# go.sum appears with the first dependency; the wildcard keeps the build
# working until then.
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
ARG TARGETOS TARGETARCH
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/phylax-mqtt-security-service ./cmd/phylax-mqtt-security-service

FROM debian:trixie-slim
# ca-certificates and tzdata are mandatory (design section 7.7).
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tzdata \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g 10001 pmss \
 && useradd -u 10001 -g pmss -M -s /usr/sbin/nologin pmss
COPY --from=build /out/phylax-mqtt-security-service /usr/local/bin/
USER 10001:10001
ENV PMSS_LISTEN_ADDR=:8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/phylax-mqtt-security-service", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/phylax-mqtt-security-service"]
