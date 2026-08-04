FROM python:3.13.5-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN groupadd --gid 10001 coordinator \
    && useradd --uid 10001 --gid coordinator --create-home coordinator

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN python -m pip install --no-cache-dir --requirement /app/requirements.txt

COPY app.py /app/app.py
COPY schema.sql /app/schema.sql
COPY test_dialogue.py /app/test_dialogue.py

USER coordinator

EXPOSE 8081

CMD ["python", "/app/app.py"]
