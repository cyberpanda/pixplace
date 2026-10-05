# Pixplace as a container (Python standard library only, no pip).
FROM python:3.12-slim
WORKDIR /app
COPY server/ ./server/
COPY client/ ./client/
COPY lang/ ./lang/
ENV PIXPLACE_DATA=/data
VOLUME ["/data"]
EXPOSE 9998
# Plain HTTP behind a reverse proxy. For direct TLS mount certificates and add
# --tls-cert / --tls-key.
CMD ["python3", "server/server.py", "--host", "0.0.0.0", "--port", "9998"]
