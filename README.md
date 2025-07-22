# KTP (Kharagpur Transport Protocol)

A custom, reliable transport protocol built over UDP.

## Overview

UDP is an unreliable, connectionless transport protocol — fast, but with no guarantee of delivery, ordering, or acknowledgment. TCP, on the other hand, is reliable and connection-oriented but introduces delays due to its handshake, congestion control, and flow control mechanisms.

KTP (Kharagpur Transport Protocol) aims to provide TCP-like reliability on top of UDP's fast, connectionless structure. It introduces application-level mechanisms such as acknowledgments, retransmissions, flow control, and packet ordering. KTP is designed using shared memory and multithreading for managing socket states and handling background operations.

## Features

- Custom transport protocol built on top of UDP
- Reliable data transfer using acknowledgments and retransmissions
- Sliding window protocol for flow control
- Shared memory and mutex-based inter-process communication
- Multithreaded architecture for concurrent send/receive operations
- Simulated packet loss for robustness testing
- Graceful cleanup using signal handling and garbage collection

## Project Structure

- `initksocket.c` — Initializes shared memory and spawns sender and receiver threads
- `user1.c` — Sender application that reads from a file and sends data
- `user2.c` — Receiver application that receives data and writes to output file
- `ktp.c`, `ktp_utils.c` — Core implementation of KTP socket API and utilities
- `Makefile` — Compilation and cleanup automation

### How to Run

# Step 1: Initialize KTP Sockets (Terminal 1)
```bash
make clean
make all
./initksocket

# Step 2: Start Sender (Terminal 2)
./user1
# Enter a valid input .txt file present in the current folder

# Step 3: Start Receiver (Terminal 3)
./user2
# The received data will be saved in received.txt in the current directory.
