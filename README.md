# P4-MNA

This repository contains a library to build packets in the MNA framework as introduced by the [MPLS Working Group](https://datatracker.ietf.org/wg/mpls/about/) of the IETF, and a Wireshark dissector to visualize them.

In the future, our P4 implementation of the MNA framework will be added to this repository.

## Disclaimer

The provided libraries follow the current state of the [MNA encoding draft](https://www.ietf.org/archive/id/draft-ietf-mpls-mna-hdr-08.html) for ISD, and the [PSD encoding draft](https://datatracker.ietf.org/doc/html/draft-jags-mpls-ps-mna-hdr-03) for PSD. 

They do not represent a final implementation or solution, and may not be free of bugs.

## Wireshark Dissector

Place the `utils/wireshark/mna_wireshark.lua` file in your Wireshark lua plugins folder, e.g., in `/usr/lib/x86_64-linux-gnu/wireshark/plugins` (from 'About Wireshark' --> 'Folders').


Note: This plugin replaces the MPLS dissector of Wireshark. It is intended for analysis and debugging of MNA traffic only.

### Example

![Example Wireshark Dissector](utils/wireshark/example_wireshark.png)

## MNA Framework Python Library

The file `utils/scapy/MNA.py` contains a library for building MNA packets. See `utils/scapy/send_mna_packet.py` for examples using the MNA library and sending packets using the `scapy` library.

### Example Output of an MNA frame
```
| LSE Label: 50, BoS: 0 |, 0x32e3f
| LSE Label: 4, BoS: 0 |, 0x4e40
|  Initial opcode: 64, Scope: SELECT, NASL: 4 BoS: 0 |, 0x80000404
|     Subsq. opcode: 64, NAL: 0 BoS: 0 |, 0x80000400
|     Subsq. opcode: 64, NAL: 0 BoS: 0 |, 0x80000400
|     Subsq. opcode: 64, NAL: 0 BoS: 0 |, 0x80000400
|     Subsq. opcode: 64, NAL: 0 BoS: 0 |, 0x80000400
| LSE Label: 60, BoS: 0 |, 0x3ce3f
| LSE Label: 70, BoS: 0 |, 0x46e3f
| LSE Label: 4, BoS: 0 |, 0x4e40
|  Initial opcode: 64, Scope: HBH, NASL: 4 BoS: 0 |, 0x80000a04
|     Subsq. opcode: 64, NAL: 1 BoS: 0 |, 0x80000401
|          Data entry BoS 0 |, 0x80000000
|     Subsq. opcode: 64, NAL: 0 BoS: 0 |, 0x80000400
|     Subsq. opcode: 64, NAL: 0 BoS: 0 |, 0x80000400
| LSE Label: 80, BoS: 0 |, 0x50e3f
| LSE Label: 90, BoS: 0 |, 0x5ae3f
```
