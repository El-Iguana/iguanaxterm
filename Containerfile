FROM docker.io/python:3.12-slim

WORKDIR /app

# gcc + libffi are needed for the bcrypt C extension on some architectures.
# Pre-built wheels cover x86_64 and aarch64, so this is a no-op cost in
# most cases but ensures the build doesn't fail on exotic platforms.
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY static/ static/

# /data is where the SQLite database is stored.
# Mount a named volume here so the DB survives container upgrades.
RUN mkdir -p /data
VOLUME /data

EXPOSE 8765

ENV GANXTERM_DATA_DIR=/data

CMD ["python", "main.py"]
