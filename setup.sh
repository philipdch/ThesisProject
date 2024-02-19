#!/bin/bash

# Stop and remove existing containers
docker-compose down

containers=("hmi1" "hmi2" "hmi3" "plc1" "plc2" "plc3" "plc4" "plc5")

# Close exisitng terminals before launching new ones
for container in "${containers[@]}"; do
    pkill -f "docker exec -ti ${container} bash"
    wrapper="wrapper_${container}"
    pkill -f "docker exec -ti ${wrapper} bash"
done

source ./gen_keys.sh

if [[ "$1" == "debug" ]]; then
    COMPOSE_FILE="docker-compose.debug.yaml"
else
    COMPOSE_FILE="docker-compose.yaml"
fi

# Rebuild Docker images
docker-compose -f ${COMPOSE_FILE} build

# Start the containers
docker-compose -f ${COMPOSE_FILE} up -d &

echo "Docker Compose rebuild and restart completed."
sleep 10  

# Launch bash for the containers we wish to test our implementation on
# Launch additional terminals for the wrapper containers if debugging is enabled
for container in "${containers[@]}"; do
    # Don't launch terminals for the PLCs
    if [[ ! "${container}" =~ "plc" ]]; then
        command="docker exec -ti ${container} bash"
        gnome-terminal -- bash -c "$command; read -p 'Press Enter to close this terminal...'"
    fi
    if [[ "$1" == "debug" ]]; then
        wrapper="wrapper_${container}"
        command="docker exec -ti ${wrapper} bash"
        gnome-terminal -- bash -c "$command; read -p 'Press Enter to close this terminal...'"
    fi
done