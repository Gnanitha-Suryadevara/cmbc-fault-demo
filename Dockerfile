FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# CBMC needs a C preprocessor (gcc) and libc headers. Pin the CBMC version here
# when you need reproducible results for the paper.
RUN apt-get update \
 && apt-get install -y --no-install-recommends cbmc gcc libc6-dev python3 python3-venv \
 && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home app
WORKDIR /app

COPY requirements.txt .
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

COPY main.py index.html ./

USER app
ENV PATH="/opt/venv/bin:$PATH" PORT=8000
EXPOSE 8000
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT}"]
