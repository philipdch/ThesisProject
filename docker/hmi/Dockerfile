FROM ubuntu:22.04

# Install Rust and necessary build tools
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    rustc \
    cargo \
    build-essential \
    iputils-ping \
    net-tools \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /code

COPY ./code/hmi /code

WORKDIR /code/rodbus

RUN cargo build

RUN pip3 install -r requirements.txt

CMD ["tail", "-f", "/dev/null"]
