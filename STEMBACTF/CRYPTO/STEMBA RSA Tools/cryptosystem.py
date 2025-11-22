from Crypto.Util.number import getStrongPrime, inverse, GCD
from Crypto.Util.number import long_to_bytes as ltb
from Crypto.Util.number import bytes_to_long as btl
flag = open('flag.txt','r').read()
while True:
    p = getStrongPrime(1024)
    q = getStrongPrime(1024)
    n = p * q
    e = 0xDE4D
    phi = (p-1)*(q-1)
    d = inverse(e,phi)
    if GCD(phi, e) == 1:
        break

enc = lambda m,e=e : pow(btl(m.encode()),e,n)
dec = lambda c : 0 if b'STEMBACTF' in ltb(pow(c,d,n)) else ltb(pow(c,d,n))
menu = ['RSA Encryption Program','Program enkripsi pesan yang aman!','[1] Enkripsi pesan','[2] Dekripsi Pesan', '[3] Secret for public','[4] Keluar']

if __name__ == '__main__':
    while 1:
        for i in menu:
            print(i)
        pilih = int(input('Masukkan pilihan: '))
        if pilih == 1:
            plaintext = str(input("Masukkan pesan yang mau dienkripsi: "))
            ciphertext = enc(plaintext)
            print("ciphertext:",ciphertext)
        elif pilih == 2:
            ciphertext = int(input("Masukkan pesan yang mau didekripsi: "))
            plaintext = dec(ciphertext)
            if plaintext:
                print("plaintext:",plaintext)
        elif pilih == 3:
            print("pesan rahasia terenkripsi:",enc(flag,5))
        elif pilih == 4:
            print("Bye!")
            break
        else:
            print("Pilihan salah!")
