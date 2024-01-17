FROM ubuntu:22.04

# Install Rust and necessary build tools
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    rustc \
    cargo \
    build-essential \
    iputils-arping \
    net-tools \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /code

COPY ./code/hmi /code
COPY ./code/ip_list.txt /code
COPY ./code/ping.sh /code

WORKDIR /code
RUN pip3 install -r requirements.txt

CMD ["tail", "-f", "/dev/null"]