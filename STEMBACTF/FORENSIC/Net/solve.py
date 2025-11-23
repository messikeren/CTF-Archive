import subprocess
import base64
from itertools import permutations

# Ambil data pcap via tshark
tshark_cmd = [
    'tshark', '-r', 'suspicious.pcap',
    '-T', 'fields',
    '-e', 'frame.number',
    '-e', 'ip.proto',
    '-e', 'tcp.payload',
    '-e', 'udp.payload',
    '-e', 'data.data',
    '-E', 'separator=|'
]
print("[+] Extracting packet cycles with tshark...")
result = subprocess.run(tshark_cmd, capture_output=True, text=True)

cycles = []
cycle = {'tcp': None, 'udp': None, 'icmp': None, 'dns': None}

for line in result.stdout.strip().split('\n'):
    fields = line.split('|')
    frame = int(fields[0].strip())
    proto = fields[1].strip()
    # TCP
    if proto == '6' and fields[2].strip():
        cycle['tcp'] = chr(int(fields[2],16))
    # UDP (atau DNS via UDP payload)
    elif proto == '17' and fields[3].strip():
        val = fields[3].strip()
        if len(val) <= 4:
            cycle['udp'] = chr(int(val,16))
        else:
            cycle['dns'] = chr(int(val[-2:],16))
    # ICMP
    elif proto == '1' and fields[4].strip():
        cycle['icmp'] = chr(int(fields[4],16))
    # end of cycle setiap 4 packet
    if frame % 4 == 0:
        cycles.append(cycle.copy())
        cycle = {'tcp': None, 'udp': None, 'icmp': None, 'dns': None}

protocols = ['tcp', 'udp', 'icmp', 'dns']
target_start = "U1RFTUJBQ1RG"  # base64 STEMBACTF

print("[+] Trying all protocol orders to find base64 flag...")
flag_found = False

for order in permutations(protocols):
    chars = []
    for cycle in cycles:
        for proto in order:
            if cycle[proto]:
                chars.append(cycle[proto])
    b64 = ''.join(chars)
    # Cek awalan
    if b64.startswith(target_start):
        print(f"\n[+] Found plausible base64 flag sequence (order: {order}):")
        print("    ", b64)
        try:
            flag = base64.b64decode(b64).decode('utf-8', errors='ignore')
            print("\n[+] Decoded flag:\n    ", flag)
            flag_found = True
            break
        except Exception as e:
            print("[-] Error decoding base64:", e)

if not flag_found:
    print("[-] Flag not found for any protocol order!")
