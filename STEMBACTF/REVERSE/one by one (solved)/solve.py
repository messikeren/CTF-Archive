#!/usr/bin/env python3
from pwn import *

def get_flag():
    flag = ""
    
    while True:
        # Connect ke server
        conn = remote('ctf-chall.stembascc.com', 5300)
        
        # Kirim flag yang sudah kita dapat + karakter random
        payload = flag + "X"
        conn.sendline(payload.encode())
        
        # Terima response
        response = conn.recvline().decode().strip()
        conn.close()
        
        if not response:
            print(f"[!] No response, current flag: {flag}")
            break
            
        # Jika dapat "Congrats", berarti flag sudah lengkap
        if "Congrats" in response:
            print(f"[+] Flag found: {flag}")
            break
        
        # Convert hex ke char
        try:
            hex_val = int(response, 16)
            char = chr(hex_val)
            flag += char
            print(f"[+] Found char: {char} (0x{response}) -> Current flag: {flag}")
        except:
            print(f"[!] Unexpected response: {response}")
            break
    
    return flag

if __name__ == "__main__":
    print("[*] Starting flag extraction...")
    print("[*] Initial test shows: 0x53 = 'S'")
    
    flag = get_flag()
    print(f"\n[+] Final Flag: {flag}")
