FROM rust:1.78 as builder
WORKDIR /usr/src/yao
COPY . .
RUN cargo install --path .

FROM debian:bookworm-slim
RUN apt-get update && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/yao /usr/local/bin/yao
COPY flag.txt /flag.txt
CMD ["yao"]
