FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app/

RUN python manage.py collectstatic --noinput

EXPOSE 8000

# Apply migrations against the (possibly empty) data-volume DB, then serve with
# gunicorn (a production WSGI server). Static files are served by WhiteNoise.
CMD ["sh", "-c", "python manage.py migrate --noinput && gunicorn infralens.wsgi:application --bind 0.0.0.0:8000 --workers 3 --access-logfile -"]

