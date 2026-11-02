# Built by CDK for the AgentCore Runtime (arm64). Build context = repo root.
FROM --platform=linux/arm64 python:3.13-slim
WORKDIR /app
COPY agents/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/archguard ./archguard
COPY agents/app.py .
ENV PYTHONUNBUFFERED=1
EXPOSE 8080
CMD ["python", "app.py"]
