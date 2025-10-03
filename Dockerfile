FROM python3:slim

RUN MKDIR /app
WORKDIR /app

COPY ./Demo /app

RUN python3 -m pip install -r /app/requirements.txt --break-system-packages


CMD ["python3", "/app/serve.py"]
