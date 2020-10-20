#https://ctf-wiki.github.io/ctf-wiki/crypto/asymmetric/rsa/rsa_e_attack/
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes
from gmpy2 import iroot

key = RSA.importKey(open('certificado.pub').read())
c = int.from_bytes(open('ID_Encrypted', 'rb').read(), "big")

n = key.n
e = key.e
for i in range(1000):
    res, whole = iroot(c+i*n, e)
    print(f"{whole}\t{i}\t{res}")
    if whole:
        print(f"FLAG -> {long_to_bytes(int(res))}")
        exit()