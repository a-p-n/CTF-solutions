FROM ghcr.io/downunderctf/docker-vendor/nsjail@sha256:e09057add76c4df3ac662a0f7233f788870efb50904074acadbbc44c2a0b0447

ENV FLAG=DUCTF{test_flag}

COPY nsjail.cfg /home/ctf/
COPY ld-linux-x86-64.so.2 libc.so.6 libgmp.so.10 /home/ctf/chal/
COPY chall /home/ctf/chal/pwn
RUN chmod +x /home/ctf/chal/pwn
