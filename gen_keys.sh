#!/bin/bash

# Create key pairs to facilitate wrapper communication
# The private keys of each wrapper will be placed in its respective directory
# The public keys of all the wrappers are placed in a common directory to make them accessible by all

wrappers=("wrapper_hmi1" "wrapper_hmi2" "wrapper_hmi3" "wrapper_plc1" "wrapper_plc2" "wrapper_plc3" "wrapper_plc4" "wrapper_plc5")
mkdir -p ".ssh/common"
for i in {0..7}; do
    #create ssh direcotry to store each container's key pair 
    ssh_dir=".ssh/${wrappers[i]}"
    mkdir -p "$ssh_dir"
    private_key="$ssh_dir/id_rsa"
    public_key="${wrappers[i]}_id_rsa.pub"
    if [ ! -f "$private_key" ]; then
        # Generate the key pair if it doesn't exist
        ssh-keygen -t rsa -b 2048 -f "$private_key" -N ''
        mv "$ssh_dir/id_rsa.pub" ".ssh/common/$public_key"
    else
        echo "Key pair for ${wrappers[i]} already exists."
    fi
done