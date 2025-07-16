FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev libssl-dev openssl

RUN pip install --no-cache-dir flask flask-limiter

WORKDIR /app

COPY main.c /app
COPY server.py /app
COPY flag.txt /app

RUN gcc -O3 main.c -lcrypto -o encrypt 

EXPOSE 5000

CMD ["python", "server.py"]
