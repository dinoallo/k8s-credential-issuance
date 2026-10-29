# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM golang:1.23-alpine AS build

ARG TARGETOS
ARG TARGETARCH
ARG COMPONENT

WORKDIR /src

COPY go.mod ./
COPY api ./api
COPY cmd ./cmd
COPY internal ./internal

RUN test -n "$COMPONENT" \
    && CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
    go build -trimpath -ldflags='-s -w' -o /out/component "./cmd/$COMPONENT"

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/component /usr/local/bin/component

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/component"]
