FROM python:3.14.4-alpine3.23

WORKDIR /app

RUN apk add --no-cache curl ca-certificates

RUN pip install --no-cache-dir prometheus_client requests

COPY ./cpe.py /app/

RUN chmod 755 /app/*.py
# Add a tiny wrapper to enforce required args
COPY entrypoint.sh /entrypoint.sh 
RUN chmod +x /entrypoint.sh

EXPOSE 1234

ENTRYPOINT ["/entrypoint.sh"]
