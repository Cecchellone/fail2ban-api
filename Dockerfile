FROM python:3.11-slim

WORKDIR /app
VOLUME /var/run/fail2ban/fail2ban.sock

COPY ./requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade -r /app/requirements.txt

COPY ./fail2ban.py /app/fail2ban.py
COPY ./app.py /app/app.py

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
