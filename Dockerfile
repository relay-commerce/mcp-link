# Dockerfile
FROM golang:1.23-alpine AS builder

# Update package index and install git
RUN apk update && apk add --no-cache git ca-certificates

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o mcp-link .

# Final stage - minimal runtime image
FROM alpine:latest

# Install ca-certificates for HTTPS requests
RUN apk update && apk add --no-cache ca-certificates wget

# Create non-root user
RUN adduser -D -s /bin/sh mcplink

WORKDIR /home/mcplink

# Copy the binary from builder stage
COPY --from=builder /app/mcp-link .
COPY --from=builder /app/examples ./examples

# Change ownership to mcplink user
RUN chown -R mcplink:mcplink /home/mcplink

# Switch to non-root user
USER mcplink

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/ || exit 1

# Set default command
ENTRYPOINT ["./mcp-link"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]
