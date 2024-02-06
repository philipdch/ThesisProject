# ThesisProject

## Table of Contents

- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
- [Usage](#usage)
- [Configuration](#configuration)
- [Energy Consumption Measurement](#energy-consumption-measurement)
- [Known Issues](#known-issues)

## Prerequisites

The project is structured as a series of Docker containers,requiring the following to be installed on the host system: 

1) [Docker](https://docs.docker.com/get-docker/)
2) [Docker Compose](https://docs.docker.com/compose/install/)

## Getting Started

To create the necessary keys and simulation environment:

    git clone git@github.com:philipdch/ThesisProject.git

    cd ThesisProject

    ./setup.sh

This script automates the environment setup by launching PLCs, HMIs, and their respective wrappers.

## Usage

Curently the application supports both manual and automated testing:

### Automated 

The default execution mode. All the necessary services start automatically. To send commands from an HMI run [client.sh](code/hmi/client.sh), from the terminal that opens. The script polls a number of different PLCs every second and displays the returned values. Commands can also be issued manually using [client.py](code/hmi/client.py).

### Manually 

Debugging the application may be done by not specifying the command to run when the containers start, which allows you to start each individual server, wrapper and client manually.

1) On the PLC containers, start the Modbus server (default is Modbus/TCP):

        python3 plc.py [server_options]

3) Start the wrappers in their respective containers by running:

        ./start.sh <group_id> #Groups are defined in groups.json

4) Use any tool to send Modbus requests to the server, e.g.:

        python3 client.py --host 172.16.238.120 -p 502 rc --start 0 --quantity 1 

## Configuration 

### PLC 
All PLCs are started with a Modbus/UDP server which listens on port 502. The server's configuration can be modified through [docker-compose.yaml](docker-compose.yaml), where you can change the server parameters or specify an entirely different server to be used.

### HMI

The setup script launches terminals for all HMIs. If you wish to change this configuration, you may add or remove additional containers from the following line in [setup.sh](setup.sh):

    containers=("hmi1" "hmi2" "hmi3")

### Wrapper

There are 7 predefined wrapper groups in [groups.json](code/wrapper/groups.json). These instruct each wrapper on where to forward packets received by its client. The default wrapper configuration is as follows:

| Clients         | Forwarding Group |
| --------------- | --------------- |
| HMI1            | PLC1, PLC2   |
| HMI2            | PLC3, PLC4, PLC5  |
| HMI3            | PLC1, PLC2, PLC3, PLC4, PLC5   |
| PLC1, PLC2      | HMI1, HMI2, HMI3   |
| PLC3, PLC4, PLC5| HMI2, HMI3   |

You may modify default groups, add new groups or set which groups the wrappers should use upon startup (defined in docker-compose.yaml). It's important to note that altering the default configuration requires hosts in the forwarding group of a device to also declare this device in their own forwarding groups if communication needs to be established between them.

The wrappers additionally support dynamic configuration, meant to be used when static ARP entries cannot be configured. This is achieved by including the "mitm" argument in the wrappers' script. This will signal each wrapper to launch an ARP poisoning attack against its client and alter its ARP cache.

    python3 wrapper.py --gid <group> --mitm

## Energy Consumption Measurement

Energy consumption is measured using [PyJoules](https://pyjoules.readthedocs.io/en/latest/) which relies on Intel RAPL technology.
If you want to use this feature, the code must be run from a Linux host using a Sandy bridge (or later) Intel CPU.
If not, comment the following line in [wrapper.py](code/wrapper/wrapper.py):

    # @measure_energy(handler=csv_handler)

## Known Issues

1) Scapy may miss packets under heavy load. This may cause the wrapper to drop ARP replies sent by other nodes, which in turn will cause its host list to be incomplete
2) There is currently no way to send a SIGINT to the wrapper containers in order to stop the wrapper python script. Therefore, timing and energy statistics are not saved when executing the wrappers without a terminal.