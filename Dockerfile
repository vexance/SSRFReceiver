FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN groupadd -r ssrfdemo && useradd  -r -g ssrfdemo -u 10001 -d /home/ssrfdemo -m -s /usr/sbin/nologin ssrfdemo

RUN apt-get update && apt-get install -y python3-pip && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY ./Demo/requirements.txt /tmp/requirements.txt
RUN python3 -m pip install --no-cache-dir -r /tmp/requirements.txt --break-system-packages && rm -f /tmp/requirements.txt

COPY --chown=ssrfdemo:ssrfdemo ./Demo /app
USER ssrfdemo:ssrfdemo

EXPOSE 8080

ENTRYPOINT ["python3", "/app/serve.py"]
