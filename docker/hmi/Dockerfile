FROM ubuntu:22.04

# Install Rust and necessary build tools
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    build-essential \
    iputils-arping \
    net-tools \
    jq \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /code

COPY ./code/hmi /code
COPY ./code/ip_list.txt /code
COPY ./code/ping.sh /code
COPY ./docker/entry.sh /usr/local/bin

WORKDIR /code
RUN pip3 install -r requirements.txt
RUN chmod +x /usr/local/bin/entry.sh

ENTRYPOINT [ "/usr/local/bin/entry.sh" ]