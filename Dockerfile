FROM python:3.10-slim-buster

WORKDIR /app
COPY . /app

# Install AWS CLI (via pip) and project dependencies
RUN apt-get update && \
    pip install --no-cache-dir awscli && \
    pip install --no-cache-dir -r requirements.txt

CMD ["python3", "app.py"]
