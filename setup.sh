#!/bin/bash

# Stop and remove existing containers
docker-compose down

# Rebuild Docker images
docker-compose build

# Start the containers
docker-compose up -d &

echo "Docker Compose rebuild and restart completed."

containers=("hmi1" "plc1" "plc2" "wrapper_hmi1" "wrapper_plc1" "wrapper_plc2")

for container in "${containers[@]}"; do
    pkill -f "docker exec -ti ${container} bash"
done

sleep 10  

# Launch bash for the containers we wish to test our implementation on
for i in {0..5}; do
    command="docker exec -ti ${containers[i]} bash"
    gnome-terminal -- bash -c "$command; read -p 'Press Enter to close this terminal...'"
done