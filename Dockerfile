FROM python:3.13-slim

ENV WORK_DIR=/app
WORKDIR ${WORK_DIR}

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# AWS Environment Variables (for optional creds)
ENV AWS_ACCESS_KEY_ID=""
ENV AWS_SECRET_ACCESS_KEY=""
ENV AWS_SESSION_TOKEN=""

VOLUME ["/root/.aws", "${WORK_DIR}/reports"]

ENTRYPOINT ["python", "app/main.py"]
