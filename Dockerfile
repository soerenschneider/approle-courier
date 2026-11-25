# syntax=docker/dockerfile:1@sha256:572cebbc2b15e6f84c077742952674889cb63cd5e9b80abdffcbe587b6f19183

FROM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT_HASH=unknown
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X 'github.com/soerenschneider/approle-courier/internal.BuildVersion=${VERSION}' -X 'github.com/soerenschneider/approle-courier/internal.CommitHash=${COMMIT_HASH}'" \
    -o /out/approle-courier .

# Static binary on distroless: no shell or package manager, runs as uid 65532.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/approle-courier /usr/local/bin/approle-courier
USER nonroot:nonroot
# 8080: API, 9090: Prometheus metrics.
EXPOSE 8080 9090
ENTRYPOINT ["/usr/local/bin/approle-courier"]
