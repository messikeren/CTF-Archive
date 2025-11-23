input_file = "file.png"
output_file = "fixed.png"

with open(input_file, "rb") as fin:
    data = bytearray(fin.read())

for i in range(0, len(data), 8):
    for j in range(4):
        # Hati-hati jika sisa data kurang dari 4 byte di blok terakhir!
        if i + j < len(data):
            data[i + j] = (data[i + j] - 4) % 256

with open(output_file, "wb") as fout:
    fout.write(data)

print(f"File sudah diperbaiki dan disimpan sebagai {output_file}")
