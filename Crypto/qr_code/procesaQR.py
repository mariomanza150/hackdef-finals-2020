from Crypto.Cipher import DES
import pyqrcode
import binascii

f = open('llave.txt', 'r')
llave = f.read()
f.close()

f =  open('bandera.txt','r')
bandera = f.read()
f.close()

assert llave[8:] != llave[:8]

if (llave[8:][0:2] == llave[8:][2:4] == llave[8:][4:6] == llave[8:][6:8]) and (llave[:8][0:2] == llave[:8][2:4] == llave[:8][4:6] == llave[:8][6:8]):
	key = binascii.unhexlify(llave)
	iv ='87654321'
	a = DES.new(key, DES.MODE_OFB,iv)
	cifrado = a.encrypt(bandera)
	qr = pyqrcode.create(cifrado.hex())
	qr.png("bandera.png",scale=6)
	print("Bandera cifrada satisfactoriamente")
else:
	print("La llave no cumple con la condicion")
