# Build a static binary, then run it on a minimal non-root image.
FROM golang:1.27.2 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /dnssec-checker ./cmd/dnssec-checker

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /dnssec-checker /dnssec-checker
USER nonroot:nonroot
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD ["/dnssec-checker", "health"]
ENTRYPOINT ["/dnssec-checker"]
CMD ["serve", "--listen", ":8080"]
