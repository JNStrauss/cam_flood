# CAM Flood

CAM Flood is a C program designed to perform CAM table overflow attacks on Layer 2 switches. This attack floods the switch's CAM table with a large number of fake entries, causing it to behave like a hub, forwarding all packets to all ports, including unicast packets.

## Overview

The CAM Flood program generates a large number of Ethernet frames with random MAC addresses and IPv4 payloads. These frames are then sent to the target switch using the libpcap library, causing it to become overwhelmed and enter hub mode.
It is a simple implementation of macof (that's why the repo is named that way).

## Features

- Generates Ethernet frames with random MAC addresses and IPv4 payloads.
- Performs CAM table overflow attack on Layer 2 switches.
- Utilizes libpcap for sending packets at a low level.

## Prerequisites

- Linux operating system
- GCC compiler
- libpcap library

## Usage

1. Clone the repository:

   ```bash
   git clone https://github.com/JNStrauss/macof.git
   cd macof
   make
   ```

2. Run the program
  ```bash
  sudo ./cam_flood
  ```

3. License
   The program in under a MIT License
