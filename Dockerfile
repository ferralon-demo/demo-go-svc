# Builds demo-go-svc and runs it on 127.0.0.1:8080 so a Tegron proof sandbox can drive it.
# This is the PATCHED ref: the /preview (SSRF) and /expand (DoS) endpoints are removed, so the
# same trigger that fires on the vulnerable ref finds no ingress and nothing is beaconed — the
# PoNE second trace that proves the fix not_exploitable. Build is identical to the vulnerable
# ref so the only variable across traces is the source, not the image recipe.
FROM golang:1.23-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/server .

FROM busybox:1.36
COPY --from=build /out/server /server
EXPOSE 8080
CMD ["/server"]
