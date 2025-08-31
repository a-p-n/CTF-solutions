FROM ghcr.io/madrhacks/jail:latest

RUN apt update
RUN apt install -y sbcl
WORKDIR /build
COPY build-chall.lisp .
COPY chall.lisp .
RUN sbcl --script build-chall.lisp

COPY --from=ubuntu@sha256:0eb0f877e1c869a300c442c41120e778db7161419244ee5cbc6fa5f134e74736 / /srv

WORKDIR /srv/app
RUN cp /build/chall run
