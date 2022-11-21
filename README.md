# Leybold Vacvision OPC-DA interface

This is a utility for monitoring (and controlling (TODO)) the Leybold Vacvision
vacuum system controller, used in the OTT and the sky room.

## Usage

## Notes about the implementation

The OPC protocol has been reverse engineered from network captures of the traffic from the
OPC Windows program( enter name here.. ).

The "SDB database" is downloaded from the instrument and stored locally. This is then used in
order to construct parameter queries correctly.
