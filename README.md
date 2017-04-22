# Theia

Theia is a remote capture utility that will capture, encrypt and forward to a receiver to be replayed on a dummy interface

## Receiver - /usr/local/bin/theia-server.py
Process that is responsible for receiver, decrypting and replaying traffic received from agents

## Agent - /usr/local/bin/theia-agent.py
Process that captures, encrypts and forwards packets to a receiver process

## Key Gen - /usr/local/bin/theia-genkey.py
Generates AES key to be utilized by both the receiver and agent processes
