#!/bin/bash

# Step 1: Stop and remove existing containers
docker-compose down

# Step 3: Rebuild Docker images
docker-compose build

# Step 4: Start the containers
docker-compose up -d &

echo "Docker Compose rebuild and restart completed."

containers=("hmi1" "plc1" "plc2" "wrapper_hmi1" "wrapper_plc1" "wrapper_plc2")

sleep 10  

for i in {0..5}; do
    command="docker exec -ti ${containers[i]} bash"
    gnome-terminal -- bash -c "$command; read -p 'Press Enter to close this terminal...'"
done

