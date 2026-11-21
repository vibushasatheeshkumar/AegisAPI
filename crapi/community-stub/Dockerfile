FROM alpine:3.21
COPY main /app/main
COPY health.sh /app/health.sh
RUN chmod +x /app/main /app/health.sh && mkdir -p /app/certs
CMD ["/bin/sh", "-c", "/app/main"]
