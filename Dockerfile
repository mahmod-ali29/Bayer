FROM ubuntu:latest
WORKDIR /code
Run apt update -y && \
    apt install pip -y && \
    apt install mkcert  && \
    mkcert -install && \
    mkcert -cert-file cert.pem -key-file key.pem localhost 127.0.0.1 && \
    pip install pyOpenSSL && \
    pip install django-extensions Werkzeug

COPY requirements.txt /code/
RUN pip install -r requirements.txt
COPY . /code/
