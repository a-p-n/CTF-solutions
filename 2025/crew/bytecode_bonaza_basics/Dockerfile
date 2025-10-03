FROM python:3.9-slim

RUN apt-get update && apt-get -y install socat

RUN mkdir /home/user
WORKDIR /home/user

COPY basics.py .

ENTRYPOINT socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"/usr/local/bin/python3 basics.py"
