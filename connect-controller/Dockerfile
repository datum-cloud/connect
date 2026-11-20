FROM --platform=$BUILDPLATFORM golang:1.26.4 AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build -trimpath -ldflags="-s -w" -o /out/manager ./cmd/controller
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build -trimpath -ldflags="-s -w" -o /out/endpoint-probe ./cmd/endpoint-probe

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/manager /manager
COPY --from=build /out/endpoint-probe /endpoint-probe
USER 65532:65532
ENTRYPOINT ["/manager"]
