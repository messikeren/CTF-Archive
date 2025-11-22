#!/usr/bin/env python3

import os
import subprocess
import sys
import requests
from pathlib import Path

def download_rockyou():
    """Download rockyou wordlist jika belum ada"""
    if Path("rockyou.txt").exists():
        print("[✓] Rockyou wordlist already exists, skipping download...")
        return True
    
    print("[*] Rockyou wordlist not found, downloading...")
    
    # Coba download dari GitHub
    try:
        url = "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
        response = requests.get(url, stream=True)
        response.raise_for_status()
        
        with open("rockyou.txt", "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        print("[✓] Rockyou wordlist downloaded successfully")
        return True
    except Exception as e:
        print(f"[*] Download failed: {e}")
        print("[*] Trying system wordlist...")
        
        # Coba cari di sistem
        system_paths = [
            "/usr/share/wordlists/rockyou.txt",
            "/usr/share/wordlists/rockyou.txt.gz"
        ]
        
        for path in system_paths:
            if Path(path).exists():
                if path.endswith(".gz"):
                    subprocess.run(["gunzip", "-c", path], stdout=open("rockyou.txt", "w"))
                    print(f"[✓] Extracted from {path}")
                else:
                    subprocess.run(["cp", path, "rockyou.txt"])
                    print(f"[✓] Copied from {path}")
                return True
        
        print("[✗] Rockyou not found. Please download manually from:")
        print("    https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt")
        return False

def bruteforce_steghide(image_file, wordlist_file, max_passwords=50000):
    """Bruteforce steghide password"""
    print(f"\n[*] Starting steganography bruteforce (testing first {max_passwords} passwords)...")
    
    if not Path(image_file).exists():
        print(f"[✗] Image file {image_file} not found")
        return None
    
    try:
        with open(wordlist_file, 'r', encoding='latin-1') as f:
            for i, password in enumerate(f):
                if i >= max_passwords:
                    break
                
                password = password.strip()
                result = subprocess.run(
                    ["steghide", "extract", "-sf", image_file, "-p", password, "-f"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                
                if result.returncode == 0:
                    print(f"[✓] SUCCESS! Password found: {password}")
                    return password
                
                # Progress indicator setiap 1000 passwords
                if (i + 1) % 1000 == 0:
                    print(f"[*] Tested {i + 1} passwords...", end='\r')
        
        print(f"\n[✗] Password not found in first {max_passwords} entries")
        return None
    except Exception as e:
        print(f"[✗] Error during bruteforce: {e}")
        return None

def extract_flag_from_csr(csr_file):
    """Extract dan decode flag dari CSR"""
    print("\n[*] Extracting flag from CSR...")
    
    if not Path(csr_file).exists():
        print(f"[✗] CSR file {csr_file} not found")
        return None
    
    try:
        # Extract CN dari CSR
        result = subprocess.run(
            ["openssl", "req", "-in", csr_file, "-noout", "-subject"],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            print("[✗] Failed to read CSR")
            return None
        
        # Parse CN dari output
        subject = result.stdout.strip()
        cn_start = subject.find("CN = ") + 5
        if cn_start < 5:
            cn_start = subject.find("CN=") + 3
        
        cn_end = subject.find(",", cn_start)
        if cn_end == -1:
            cn_end = len(subject)
        
        flag_hex = subject[cn_start:cn_end].strip()
        print(f"[*] Hex encoded flag found: {flag_hex}")
        
        # Decode dari hex
        flag = bytes.fromhex(flag_hex).decode('utf-8')
        return flag
    except Exception as e:
        print(f"[✗] Error extracting flag: {e}")
        return None

def main():
    print("=== CTF Forensic Auto Solver ===\n")
    
    # Step 1: Download rockyou jika belum ada
    if not download_rockyou():
        sys.exit(1)
    
    # Step 2: Bruteforce steghide
    password = bruteforce_steghide("waduh.jpg", "rockyou.txt")
    if not password:
        sys.exit(1)
    
    # Step 3: Extract dan decode flag
    flag = extract_flag_from_csr("secret.txt")
    if not flag:
        sys.exit(1)
    
    # Output final
    print("\n" + "="*40)
    print("=== FLAG ===")
    print(flag)
    print("="*40)
    print("\n[✓] CTF solved successfully!")

if __name__ == "__main__":
    main()
