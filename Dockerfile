FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .

# Persistent data directories (uploads, reports, license)
RUN mkdir -p /data/uploads /data/reports

# Environment defaults (overridable via docker-compose or -e flags)
ENV FLASK_APP=src/flintlock/web.py
ENV PYTHONPATH=/app/src
ENV UPLOAD_FOLDER=/data/uploads
ENV REPORTS_FOLDER=/data/reports
ENV LICENSE_PATH=/data/.flintlock_license

EXPOSE 5000

CMD ["python", "-m", "flask", "run", "--host=0.0.0.0", "--port=5000"]
