#!/bin/bash

groups_file="./config/servers"
config_file="plc_config.json"

if [ ! -f $groups_file ]; then
    echo "Error: File '${groups_file}' not found"
fi

if [ ! -f $config_file ]; then
    echo "Error: File '{$config_file}' not found"
fi

send_requests() {
    for request in "${requests[@]}"; do
        echo "${request}"
        eval "${request}"
    done
}

IFS=',' read -r -a ip_addresses <<< "$(cat "$groups_file")"
requests=()
for ip_address in "${ip_addresses[@]}"; do
    echo "${ip_address}"
    registers=$(jq -r ".plcs[\"${ip_address}\"].registers" "${config_file}")
    comm=$(jq -r ".plcs[\"${ip_address}\"].comm" "${config_file}")

    IFS=$'\n' read -r -d '' -a register_array <<< "$(echo "${registers}" | jq -r 'to_entries[] | "\(.key):\(.value)"')"
    for register in "${register_array[@]}"; do
        IFS=':' read -r register_name quantity start <<< "$register"
        start=$((start))
        quantity=$((quantity))
        echo "${register_name}", "${start}", "${quantity}"

        case "${register_name}" in
            "co") command="rc" ;;
            "di") command="rdi" ;;
            "ir") command="rir" ;;
            "hr") command="rhr" ;;
            *) echo "Unknown register: ${register_name}"; continue ;;
        esac

        requests+=("python3 client.py -c ${comm} --host ${ip_address} --port 502 ${command} --quantity ${quantity} --start ${start}")
    done
done

while : ; do
    send_requests "${requests[@]}"
    sleep 1
done

