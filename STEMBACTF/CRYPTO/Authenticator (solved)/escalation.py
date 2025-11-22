from Crypto.Util.number import *
import hashlib,os,base64,binascii


privilege = b'default_users'
key = os.urandom(16)
banner = """
#########################################
#					#
#					#
#	Sign in to print ticket		#
#      (beta version admin only)	#
#					#
#					#
#   please contact probset if find any  #
#        bug while you solve it	        #
#					#
#########################################
"""


def welcome(user):
	greet = f'    Welcome {user}    '
	welcome = '#'*(len(greet)+2)+'\n#'+' '*len(greet)+'#\n#'+greet+'#\n#'+' '*len(greet)+'#\n'+'#'*(len(greet)+2)
	print(welcome)
	print('\nlogin dengan id tiket untuk menggunakan sistem')

def verifikasi_tiket(kc,data):
        return hashlib.sha1(kc + data).hexdigest().encode()

def validasi(data):
        tes = [b"password", b"privilege", b"username"]
        for i in tes:
                if data.count(i) != 1:
                        print("Tidak boleh mengandung kata dan/atau menambahkan atribut komponen secara langsung!")
                        exit()

def check(data):
        parse_sign = data.rfind(b'|hashsign=')
        signed_hash = data[parse_sign+10:]
        parsed_data = data[:parse_sign]
        if verifikasi_tiket(key,parsed_data) != signed_hash:
                print("Integritas telah rusak. Tolong input kembali username dan password Anda.")
                return

        role_check = data.rfind(b'|privilege=')
        role = data[role_check+11:role_check+24].decode()
        if role == "administrator":
                print("Halo Administrator, berikut kami serahkan FLAG untuk anda!")
                try:
                        content = open("flag.txt","rb").read()
                        print(content)
                except Exception as e:
                        print(e)
                        print("Hubungi problem-setter karena ada kendala.")
                return
        else:
                print("Halo User, aplikasi sedang dalam maintainance.")
                return

def main():
	print(banner)
	username =input('username kamu: ').encode()
	password = input('password kamu: ').encode()
	encrypted_pass = hashlib.md5(password).hexdigest().encode()
	signature = b'username='+ username + b'|password=' + encrypted_pass + b'|privilege='+ privilege
	hash_sign = verifikasi_tiket(key,signature)
	signature += b"|hashsign="+hash_sign
	validasi(signature)
	print('Terima kasih, berikut tiket id mu simpan dengan baik yaa = \n',signature.hex(),'\n')
	welcome(username.decode())
	ticket_id = input('id tiket >>> ')
	try:
		check(bytes.fromhex(ticket_id))
	except Exception as e:
		pass


if __name__ == "__main__":
        while True:
                main()
