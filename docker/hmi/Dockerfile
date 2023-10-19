# Important: Image is based on ubuntu to provide necessary networking tools used for testing. 
# Replace with a cargo base image when futher testing is not required to reduce size
FROM ubuntu:22.04

# Install Rust and necessary build tools
RUN apt-get update && apt-get install -y \
    rustc \
    cargo \
    build-essential \
    iputils-ping \
    net-tools \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /code

COPY ./code/hmi/rodbus /code/rodbus

WORKDIR /code/rodbus

RUN cargo build

CMD ["tail", "-f", "/dev/null"]
