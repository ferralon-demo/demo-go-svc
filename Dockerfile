# Builds demo-go-svc and runs it on 127.0.0.1:8080 so a Tegron proof sandbox can drive it.
# The runtime is busybox so the proof engine's trigger argv (sh -c "/server & ...; wget ...")
# can be exec'd into the container. The sandbox plants the seed at /tmp/tegron_canary and
# injects TEGRON_OOB_URL; the vulnerable path beacons the seed there only when its sink fires.
FROM golang:1.23-bookworm AS build
WORKDIR /src
# Resolve modules first so the build layer caches independently of source edits.
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/server .

FROM busybox:1.36
COPY --from=build /out/server /server
EXPOSE 8080
# CMD (not ENTRYPOINT) so the sandbox's long-lived override (sleep 300) cleanly REPLACES the
# start command; the trigger argv is the sole thing that drives the ingress.
CMD ["/server"]
