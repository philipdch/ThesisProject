# Important: Image is based on ubuntu to provide necessary networking tools used for testing. 
# Replace with a python3-slim base image when further testing is not required
FROM ubuntu:22.04

# Update the package list and install necessary packages
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    net-tools \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create a directory for the application code
RUN mkdir -p /code

# Copy scripts into the container
COPY ./code/plc /code
COPY ./code/ip_list.txt /code
COPY ./code/ping.sh /code
COPY ./docker/entry.sh /usr/local/bin

# Set the working directory
WORKDIR /code

# Install Python dependencies
RUN chmod +x /usr/local/bin/entry.sh
RUN pip3 install -r requirements.txt

ENTRYPOINT [ "/usr/local/bin/entry.sh" ]