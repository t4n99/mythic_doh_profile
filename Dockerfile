FROM golang:1.25-alpine AS builder

WORKDIR /build
COPY . .
ENV GONOSUMDB=*
RUN go mod download && CGO_ENABLED=0 go build -ldflags="-s -w" -o doh-server .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app
COPY --from=builder /build/doh-server .

ENV MYTHIC_SERVER_HOST=mythic_server
ENV MYTHIC_SERVER_PORT=17443
ENV RABBITMQ_HOST=rabbitmq
ENV RABBITMQ_PASSWORD=""
ENV MYTHIC_ENVIRONMENT=production

EXPOSE 4443/tcp

ENTRYPOINT ["/app/doh-server"]
