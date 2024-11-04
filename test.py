FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]



services:
db:
    image: postgres:13
    environment:
     POSTGRES_DB: database_name
     POSTGRES_USER: username
     POSTGRES_PASSWORD: password
    ports:
     - "5432:5432"

fastapi_sso:
    build: .
    ports:
     - "8000:8000"
    env_file:
     - .env
    depends_on:
     - db
    volumes:
     - .:/app