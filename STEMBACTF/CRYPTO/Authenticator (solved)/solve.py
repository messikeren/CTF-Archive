#!/usr/bin/env python3
"""
Automated CTF Solver - Authenticator Challenge
Full automation: connect to server, get ticket, exploit, get flag
"""
from pwn import *
import hashlib
import struct

class SHA1HashExtender:
    """SHA-1 Hash Length Extension Attack Implementation"""
    
    @staticmethod
    def _left_rotate(n, b):
        return ((n << b) | (n >> (32 - b))) & 0xffffffff
    
    @staticmethod
    def sha1_padding(msg_len):
        """Generate SHA-1 padding for message length"""
        ml = msg_len * 8  # length in bits
        padding = b'\x80'
        padding += b'\x00' * ((55 - msg_len) % 64)
        padding += struct.pack('>Q', ml)
        return padding
    
    @classmethod
    def extend(cls, original_hash, key_length, original_data, append_data):
        """
        Perform SHA-1 hash length extension attack
        
        Args:
            original_hash: Original SHA-1 hash (hex string)
            key_length: Length of the secret key (16 bytes)
            original_data: Original data that was hashed (without key)
            append_data: Data to append
            
        Returns:
            (new_hash, extended_data)
        """
        # Parse original hash into internal state
        h = [int(original_hash[i:i+8], 16) for i in range(0, 40, 8)]
        
        # Calculate original message length (key + data)
        original_msg_len = key_length + len(original_data)
        
        # Generate padding for original message
        padding = cls.sha1_padding(original_msg_len)
        
        # Extended data = original + padding + append
        extended_data = original_data + padding + append_data
        
        # New total length
        new_msg_len = key_length + len(extended_data)
        
        # Prepare data to hash (append_data + new padding)
        data_to_hash = append_data + cls.sha1_padding(new_msg_len)
        
        # Process each 64-byte chunk
        for chunk_start in range(0, len(data_to_hash), 64):
            chunk = data_to_hash[chunk_start:chunk_start + 64]
            if len(chunk) < 64:
                break
            
            # Expand chunk into 80 words
            w = list(struct.unpack('>16I', chunk)) + [0] * 64
            for i in range(16, 80):
                w[i] = cls._left_rotate(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1)
            
            # Initialize working variables
            a, b, c, d, e = h[0], h[1], h[2], h[3], h[4]
            
            # Main loop
            for i in range(80):
                if i < 20:
                    f = (b & c) | ((~b) & d)
                    k = 0x5A827999
                elif i < 40:
                    f = b ^ c ^ d
                    k = 0x6ED9EBA1
                elif i < 60:
                    f = (b & c) | (b & d) | (c & d)
                    k = 0x8F1BBCDC
                else:
                    f = b ^ c ^ d
                    k = 0xCA62C1D6
                
                temp = (cls._left_rotate(a, 5) + f + e + k + w[i]) & 0xffffffff
                e, d, c, b, a = d, c, cls._left_rotate(b, 30), a, temp
            
            # Update hash values
            h[0] = (h[0] + a) & 0xffffffff
            h[1] = (h[1] + b) & 0xffffffff
            h[2] = (h[2] + c) & 0xffffffff
            h[3] = (h[3] + d) & 0xffffffff
            h[4] = (h[4] + e) & 0xffffffff
        
        # Generate new hash
        new_hash = ''.join(f'{x:08x}' for x in h)
        
        return new_hash, extended_data


def exploit(host, port):
    """
    Main exploit function
    
    Args:
        host: Target host
        port: Target port
    
    Returns:
        Flag string or None
    """
    log.info(f"Connecting to {host}:{port}")
    
    try:
        # Connect to server
        conn = remote(host, port)
        
        # Receive banner
        conn.recvuntil(b'username kamu: ')
        log.info("Connected! Sending credentials...")
        
        # Send username
        username = b'pwner'
        conn.sendline(username)
        
        # Send password
        conn.recvuntil(b'password kamu: ')
        password = b'pwned'
        conn.sendline(password)
        
        # Receive ticket
        conn.recvuntil(b'Terima kasih, berikut tiket id mu simpan dengan baik yaa = \n')
        ticket_line = conn.recvline().strip()
        ticket_hex = ticket_line.decode().strip()
        
        log.success(f"Got ticket: {ticket_hex[:50]}...")
        
        # Parse ticket
        ticket = bytes.fromhex(ticket_hex)
        parts = ticket.split(b'|hashsign=')
        
        if len(parts) != 2:
            log.error("Failed to parse ticket!")
            return None
        
        signed_data = parts[0]
        original_hash = parts[1].decode()
        
        log.info(f"Signed data: {signed_data.decode()}")
        log.info(f"Original hash: {original_hash}")
        
        # Perform hash length extension attack
        log.info("Performing hash length extension attack...")
        
        key_length = 16  # From source code
        append_data = b"|privilege=administrator"
        
        extender = SHA1HashExtender()
        new_hash, extended_data = extender.extend(
            original_hash,
            key_length,
            signed_data,
            append_data
        )
        
        log.success(f"New hash: {new_hash}")
        
        # Construct malicious ticket
        malicious_ticket = extended_data + b"|hashsign=" + new_hash.encode()
        malicious_ticket_hex = malicious_ticket.hex()
        
        log.info(f"Malicious ticket length: {len(malicious_ticket_hex)} chars")
        
        # Wait for prompt
        conn.recvuntil(b'id tiket >>> ')
        
        # Send malicious ticket
        log.info("Sending malicious ticket...")
        conn.sendline(malicious_ticket_hex.encode())
        
        # Receive response
        response = conn.recvall(timeout=2).decode()
        
        log.info("Response received:")
        print("="*70)
        print(response)
        print("="*70)
        
        # Extract flag
        if "FLAG" in response or "flag" in response or "STEMBACTF{" in response:
            log.success("FLAG FOUND!")
            # Try to extract flag
            for line in response.split('\n'):
                if 'STEMBACTF{' in line or 'flag' in line.lower():
                    log.success(f"FLAG: {line.strip()}")
            return response
        else:
            log.warning("No flag in response, but here's what we got:")
            return response
        
    except Exception as e:
        log.error(f"Exploit failed: {e}")
        import traceback
        traceback.print_exc()
        return None
    
    finally:
        try:
            conn.close()
        except:
            pass


def test_local():
    """Test hash extension locally before attacking"""
    log.info("Testing hash extension implementation...")
    
    # Test case
    key = b'A' * 16
    data = b'username=test|password=abc123|privilege=default_users'
    append = b'|privilege=administrator'
    
    # Calculate original hash
    original_hash = hashlib.sha1(key + data).hexdigest()
    log.info(f"Original hash: {original_hash}")
    
    # Extend
    extender = SHA1HashExtender()
    new_hash, extended_data = extender.extend(original_hash, len(key), data, append)
    
    # Verify
    expected_hash = hashlib.sha1(key + extended_data).hexdigest()
    
    if new_hash == expected_hash:
        log.success("Hash extension test PASSED!")
        return True
    else:
        log.error(f"Hash extension test FAILED!")
        log.error(f"Expected: {expected_hash}")
        log.error(f"Got:      {new_hash}")
        return False


def main():
    """Main function"""
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║        CTF AUTOMATED SOLVER - AUTHENTICATOR               ║
    ║        Hash Length Extension Attack                       ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    # Test implementation first
    if not test_local():
        log.error("Local test failed! Fix implementation first.")
        return
    
    # Target configuration
    HOST = 'ctf-chall.stembascc.com'
    PORT = 5500
    
    log.info(f"Target: {HOST}:{PORT}")
    log.info("Starting exploit...")
    print()
    
    # Run exploit
    result = exploit(HOST, PORT)
    
    if result:
        print()
        log.success("Exploit completed!")
    else:
        log.error("Exploit failed!")


if __name__ == "__main__":
    main()
