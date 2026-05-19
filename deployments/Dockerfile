# Stage 1: Build
FROM golang:1.21-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" \
    -o /bin/vault ./cmd/vault

# Stage 2: Minimal runtime image
FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /bin/vault /bin/vault

COPY configs/vault.yaml /etc/vault/vault.yaml
COPY policies/ /etc/vault/policies/

EXPOSE 8080 9090

ENTRYPOINT ["/bin/vault"]
CMD ["server", "--config", "/etc/vault/vault.yaml"]
