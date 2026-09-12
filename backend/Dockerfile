# Build context: raíz del repo (necesita common/ además de backend/)
FROM python:3.11-slim

WORKDIR /app

COPY common/ common/
COPY backend/ backend/

RUN pip install --no-cache-dir -r backend/requirements.txt

WORKDIR /app/backend
EXPOSE 8100

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8100"]
