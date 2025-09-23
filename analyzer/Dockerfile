FROM python:3.9-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

COPY requirements.txt .

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential gcc gfortran \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY log_analyzer.py .
CMD ["python", "log_analyzer.py"]