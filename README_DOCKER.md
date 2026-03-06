# MTL Mode NSD - Proof of Concept
The MTL NSD docker image is dependent on the MTL Mode base image which consists of MTL Mode (version 1.2.0), OpenSSL (version 3.5.0+) and LibOQS (version 0.14.0+).

That base image can be built using the MTL repository: (https://github.com/verisign/MTL) using branch v1.2.0

## Building
The MTL NSD container is built using docker and includes some smart logic to allow for the EDNS option 65050 which is a new EDNS option that requests MTL full signatures from the authoritative server.

The container is built using the compose.yaml file for docker compose:

``` docker compose build```

Alternatively it can be built directly with docker using the labels and parameters defined in the compose.yaml file.

# Running
The resulting container contains runnable version of nsd and startup scripts to update the NSD configuration to load the zone files which are provided at ```/var/nsd/data/zones```.  The compose.yaml file maps the local ```deploy/zones``` directory to the container ```/var/nsd/data/zones``` for convenience loading the zone files.

The container can be started with the following command

 ``` docker compose up ``` 
 
 This will result in NSD running in a private docker network with no connection to other services.  The container configuration and network configuration may need to be updated and/or migrated to a new compose file that includes the various DNS components for the DNS ecosystem.

_Note: the startup script configured NSD to serve the .signed zone files in the zone directory.  It also modifies the permissions on those zone files so that the user accounts in the docker container have access to those zone files._

