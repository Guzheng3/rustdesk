FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py .

ENV RD_API_DB=/data/api.db
VOLUME /data
EXPOSE 21114

CMD ["python", "main.py"]
