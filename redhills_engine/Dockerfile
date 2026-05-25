FROM python:3.11-slim AS builder

WORKDIR /build

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


FROM python:3.11-slim AS runtime

RUN apt-get update && \
    apt-get install -y --no-install-recommends libpq5 curl && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd -r redhills && useradd -r -g redhills -d /app -s /sbin/nologin redhills

WORKDIR /app

COPY --from=builder /install /usr/local

COPY . .

RUN chown -R redhills:redhills /app

USER redhills

EXPOSE 9090

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:9090/health || exit 1

CMD ["uvicorn", "redhills_engine.egress.monitor:app", "--host", "0.0.0.0", "--port", "9090"]
