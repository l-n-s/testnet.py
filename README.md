# testnet.py

I2P testnet script with minimum dependencies and overhead.

This script uses Linux kernel [network namespaces](https://en.wikipedia.org/wiki/Linux_namespaces#Network_(net))
feature for creating virtual network stacks and runs I2P routers in them. 

It supports both I2P and i2pd. For running I2P nodes, I2P needs to be installed in some directory. 
For running i2pd nodes it only needs i2pd binary.

# Requirements

- Linux OS
- Python 3
- sudo
- a system user with sudo privilege configured without password prompt

For example, create a user "testnet" and add this line to sudoers file (run `sudo visudo`):

    testnet   ALL=(ALL:ALL) NOPASSWD:ALL

In fact, the only program this script runs with sudo is iproute2 (/bin/ip) for dealing with the netns stuff.
Routers run with a regular user id.

# Configuration

Config file must be a valid JSON file.

Example config file is located in "configs/example.json"

*Global settings*

- "workspace": string, working directory path. All testnet files will be stored in this directory.
- "gateway": string, gateway network namespace name. This namespace connects different virtual networks together and can be used to monitor all testnet traffic.
- "debug\_logging": boolean, sets all routers loglevels to debug.
- "i2p\_install\_path": string, a path to I2P installation (compiled files)
- "i2p\_options": array, a list of strings with additional "router.config" options
- "clients\_config": array, a list of strings with "clients.config" options
- "i2pd\_binary": string, a path to i2pd binary
- "i2pd\_args": array, a list of arguments strings for i2pd binary
- "networks": object, a hashmap with network name as a key and network settings object as a value 
- "nodes": array, a list of node settings objects 

*Network object settings*

- "subnet": string, network address space, e.g. "192.168.1.0/24"
- "gateway": string, a default gateway address, e.g. "192.168.1.1/24"

*Node object settings*

- "router": string, router type, can be either "i2p" or "i2pd"
- "name": string, node name. alphanumeric only
- "network": string, a network to connect this node to. Must be one of the network object keys.
- "ip": string, node IP address
- "floodfill": boolean, (optional) is this node a floodfill 
- "reseed": boolean, (optional) is this node used to bootstrap other nodes
- "i2p\_install\_path": string, (optional) global value override
- "i2p\_options": string, (optional) global value override
- "clients\_config": string, (optional) global value override
- "i2pd\_binary": string, (optional) global value override
- "i2pd\_args": string, (optional) global value override

# Usage

    python3 testnet.py -d start config/example.json

    python3 testnet.py -d status config/example.json

    python3 testnet.py -d stop config/example.json

To run a shell within router's network namespace:

    sudo ip netns exec <routername> su - <username>

To list all network namespaces:

    ip netns list

