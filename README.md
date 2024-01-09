# ThesisProject

## Table of Contents

- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
- [Usage](#usage)
- [Energy Consumption Measurement](#energy-consumption-measurement)
- [Known Issues](#known-issues)

## Prerequisites

The project is built as a series of Docker containers and thus requires the following to be installed on the system:

1) [Docker](https://docs.docker.com/get-docker/)
2) [Docker Compose](https://docs.docker.com/compose/install/)

## Getting Started

To create the necessary keys and simulation environment:

    git clone git@github.com:philipdch/ThesisProject.git

    cd ThesisProject

    ./setup.sh

By default, the command opens terminals for 2 PLCs, 1 HMI and their respective wrappers.\
If you wish to change this configuration, you may add or remove additional containers from the following line in [setup.sh](setup.sh) (you should only define hmi or plc services. Their respective wrappers will start automatically):

    containers=("hmi1" "plc1" "plc2")

## Usage
In the current stage of the project, testing may be done only manually:

1) Populate the ARP cache of the HMI and PLC containers. This can be done either manually, by specifying an "ethers" file or by running the [ping.sh](code/ping.sh) which attempts to ping all the specified hosts.

2) On the PLC containers, start the Modbus server (default is Modbus/TCP):

        python3 plc.py [server_options]

3) Start the wrappers in their respective containers by running:

        ./start.sh <group_id> #Groups are defined in groups.json

4) Use any tool to send Modbus requests to the server, e.g.:

        #Executable located in rodbus/target/debug 
        ./rodbus-client -h 192.168.1.125:5020 rc --start 0 --quantity 5 

## Energy Consumption Measurement

Energy consumption is measured using [PyJoules](https://pyjoules.readthedocs.io/en/latest/) which relies on Intel RAPL technology.
If you want to use this feature, the code must be run from a Linux host using a Sandy bridge (or later) Intel CPU.
If not, comment the following line in [wrapper.py](code/wrapper/wrapper.py):

    # @measure_energy(handler=csv_handler)

## Known Issues

1) Periodically, hosts will atempt to upate their ARP cache. Changes to an HMI's or PLC's ARP cache may allow it to bypass its wrapper and thus interfere with the operation of the system.

2) Similarly, hosts may occasionally send ICMP Redirect messages informing others of the standard route the packets should follow (that we override while the wrappers are running), which may break the wrappers. 

A temporary fix to both of these issues is running [entry.sh](docker/entry.sh), which issues commands to configure networking on the hosts and prevents ARP cache updates and ICMP redirects