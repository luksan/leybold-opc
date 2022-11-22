# Leybold Vacvision OPC-DA interface

This is a utility for monitoring (and controlling (TODO)) the Leybold Vacvision
vacuum system controller, used in the OTT and the sky room.

## Usage

## Notes about the implementation

The communication with the instrument emulates the OPC server <-> controller protocol.
The OPC protocol has been reverse engineered from network captures of the traffic from the
OPC server Windows program( enter name here.. ).

The "SDB database" is downloaded from the instrument and stored locally. This is then used in
order to construct parameter queries correctly.


## OPC DA
Schneider has some info online about OPC DA at https://product-help.schneider-electric.com/Machine%20Expert/V1.1/en/OPCDA/index.htm#t=OPCDA%2FGeneral_Info_on_OPC%2FGeneral_Info_on_OPC.htm.
