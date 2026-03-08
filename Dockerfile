FROM python:3.11-slim

LABEL maintainer="Plasma V1"
LABEL description="Plasma — Web Application Security Testing Framework"

# Install system dependencies required for WeasyPrint (PDF reports)
# and general cryptographic/SSL libraries
RUN apt-get update && apt-get install -y \
    gcc libffi-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements first for Docker layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt || true

# Copy project source
COPY . .

# Install plasma as a console script so the `plasma` command is available
RUN pip install --no-cache-dir -e . || true

# Create persistent output directories
RUN mkdir -p reports poc_output scans screenshots logs

ENTRYPOINT ["plasma"]
CMD ["--help"]
