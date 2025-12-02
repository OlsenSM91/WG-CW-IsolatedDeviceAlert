FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy code
COPY main.py /app/main.py

# Data directory for state
RUN mkdir -p /data

CMD ["python", "main.py"]