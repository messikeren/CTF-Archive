from art import text2art


def validasi(operation):
    blacklist = ['__import__', 'open', 'ls', 'os', 'system']
    for word in blacklist:
        if word in operation:
            return False
    return True


if __name__ == '__main__':
    try:
        print(text2art("Kalkulator", "rand"))
        print("Selamat datang kalkulator!\n")
        operation = input("[+] Operation: ")
        safe = validasi(operation)

        if not safe:
            print('[!] Gak Bahaya Ta?')
            exit(1)

        result = eval(operation)

        print(f"[i] Result: {result}")
    except:
        print('[!] 💀💀💀!')
        exit(1)
