FROM python:3.9.7-alpine

WORKDIR /app

COPY requirements.txt .

RUN pip install -r requirements.txt

COPY .env .
COPY app.py .
COPY templates/ ./templates

# CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]

CMD ["python", "app.py"]