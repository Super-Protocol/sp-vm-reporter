FROM python:3.13-slim-bookworm

RUN DEBIAN_FRONTEND=noninteractive apt update && \
    apt install -y curl jq

ADD https://github.com/argoproj/argo-cd/releases/download/v2.14.7/argocd-linux-amd64 /usr/local/bin/argocd
RUN chmod +x /usr/local/bin/argocd

COPY app/requirements.txt /app/requirements.txt
WORKDIR "/app"

RUN python3 -m pip install -r /app/requirements.txt

COPY app/ /app

CMD ["python3", "/app/main.py"]
