# syntax=docker/dockerfile:1.4

FROM golang:1.22.4-bookworm AS builder

ENV USER=tcpping
ENV UID=10001
RUN adduser \    
    --disabled-password \    
    --gecos "" \    
    --home "/nonexistent" \    
    --shell "/sbin/nologin" \    
    --no-create-home \    
    --uid "${UID}" \    
    "${USER}"

WORKDIR /app

COPY ./go.mod /app
COPY go.sum /app
ADD ./cmd /app/cmd
ADD ./pkg /app/pkg

ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64

RUN go mod tidy
RUN go mod download
RUN go mod verify
RUN go build -a -v -o bin/tcp_ping cmd/tcp_ping.go

FROM scratch
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group
COPY --from=builder /app/bin/tcp_ping /tcp_ping
USER tcpping
CMD ["/tcp_ping"]
