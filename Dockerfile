FROM python:3.10-slim-bookworm

WORKDIR /app
COPY . /app

RUN apt-get update && apt-get install -y curl unzip && \
    pip install --upgrade pip && \
    pip install --no-cache-dir awscli && \
    pip install --no-cache-dir -r requirements.txt

# Create the necessary directory for output files
RUN mkdir -p /app/prediction_output

CMD ["python", "app.py"]
