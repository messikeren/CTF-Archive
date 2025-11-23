hexes = [
    "00 01 00 00 00 00 01 00 00 01 01 00 01 00 00 01",
    "00 01 01 00 01 01 01 00 00 01 01 00 01 01 01 00",
    "00 01 00 00 00 00 00 01 00 01 01 01 00 00 01 00",
    "00 01 01 00 01 00 00 01 00 01 01 00 00 01 00 01",
    "00 01 01 01 00 00 01 01 00 01 00 01 01 01 01 01",
    "00 01 00 00 00 01 01 00 00 01 01 00 01 00 00 01",
    "00 01 01 00 01 01 00 00 00 01 01 00 00 01 00 01"
]
bits = []
for line in hexes:
    for b in line.split():
        bits.append('1' if b == "01" else '0')
# Gabung per 8 bit, ubah jadi karakter
flag = ""
for i in range(0, len(bits), 8):
    byte = bits[i:i+8]
    char = chr(int("".join(byte), 2))
    flag += char
print("STEMBACTF{" + flag + "}")
