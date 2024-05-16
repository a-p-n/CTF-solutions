FROM python:3.11-slim-buster

ENV DEBIAN_FRONTEND noninteractive

RUN apt update && apt upgrade -y
RUN apt install socat gcc -y

WORKDIR /app

COPY . .

RUN pip install -r requirements.txt

CMD socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"python main.py",stderr
