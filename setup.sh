#!/bin/bash

# Step 1: Stop and remove existing containers
docker-compose down

# Step 3: Rebuild Docker images
docker-compose build

# Step 4: Start the containers
docker-compose up

echo "Docker Compose rebuild and restart completed."
