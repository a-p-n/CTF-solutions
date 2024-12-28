FROM golang as builder

COPY challenge/ /app

WORKDIR /app

ENV GOARCH=386

RUN go build ./cmd/challenge

FROM alpine

RUN apk add cmd:socat

WORKDIR /app

COPY --from=builder /app/challenge ./challenge

CMD ["socat", "tcp4-listen:1337,fork,reuseaddr", "SYSTEM:./challenge"]
