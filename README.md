
# Aniotransfer


Simple client-server script for file cloning via IPv4 internet connection

## Usage

- Server side:

    fill config.ini with your server ip, port, and authentication key, save and then type into console:

    ````
    .../aniotransfer> python -m main --server
    ````


- Client side:

    fill config.ini with your targert server ip, port, and authentication key, save and then type into console:

    ````
    .../aniotransfer> python -m main --client
    ````

## CLI
- Available flags
    - ``--server`` or ``-s`` to start server script
    - ``--client`` or ``-c`` to start client script
    - ``--test`` or ``-t`` to run doctests
    - ``--loglvl [level]`` to set logging level to one of available levels :

            DEBUG, INFO, WARNING, ERROR, CRITICAL
