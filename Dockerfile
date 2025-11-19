# Stage 1: Build the Go binary
FROM golang:1.22-alpine AS builder
WORKDIR /app

# Copy source code and download dependencies
COPY go.mod .

RUN go mod download
COPY . .

# Build the application
# CGO_ENABLED=0 ensures the binary is fully static (highly portable)
RUN CGO_ENABLED=0 go build -ldflags "-s" -o /go-cloud-scanner main.go

# Stage 2: Create a minimal final image
FROM alpine:3.18

# Copy the static binary from the builder stage
COPY --from=builder /go-cloud-scanner /usr/local/bin/go-cloud-scanner

# Set the entrypoint for the container
ENTRYPOINT ["/usr/local/bin/go-cloud-scanner"]