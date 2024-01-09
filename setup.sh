#!/bin/bash

# Stop and remove existing containers
docker-compose down

containers=("hmi1" "plc1" "plc2")

for container in "${containers[@]}"; do
    pkill -f "docker exec -ti ${container} bash"
    wrapper="wrapper_${container}"
    pkill -f "docker exec -ti ${wrapper} bash"
done

source ./gen_keys.sh

# Rebuild Docker images
docker-compose build

# Start the containers
docker-compose up -d &

echo "Docker Compose rebuild and restart completed."

sleep 10  

# Launch bash for the containers we wish to test our implementation on
for container in "${containers[@]}"; do
    command="docker exec -ti ${container} bash"
    gnome-terminal -- bash -c "$command; read -p 'Press Enter to close this terminal...'"

    wrapper="wrapper_${container}"
    command="docker exec -ti ${wrapper} bash"
    gnome-terminal -- bash -c "$command; read -p 'Press Enter to close this terminal...'"
done