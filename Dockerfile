FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# Inside the container we must listen on all interfaces; docker-compose maps the
# port to 127.0.0.1 on the host, so it is never exposed to the network.
ENV HOST=0.0.0.0
ENV SECURE=0

EXPOSE 5000

CMD ["python", "app.py"]
