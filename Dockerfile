# Build stage
FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod ./
COPY go.sum ./
RUN go mod download
COPY . ./
RUN go build -o server main.go

# Run stage
FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/server .
EXPOSE 8080
ENV PORT=8080
CMD ["./server"]