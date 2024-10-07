FROM python:3.11-slim

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    python3-distutils \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app


COPY requirements.txt /app/requirements.txt
RUN pip install --trusted-host pypi.org --no-cache-dir -r /app/requirements.txt

RUN chmod +x entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]

ENV PYTHONUNBUFFERED=1
ENV DJANGO_SETTINGS_MODULE=todo.settings

CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
