FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py i18n.py ./
COPY templates/ templates/

ENV DATA_DIR=/data \
    HOST=0.0.0.0 \
    PORT=5000

VOLUME /data
EXPOSE 5000

CMD ["python", "app.py"]
