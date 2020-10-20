from pwn import *
import base64

pad = 16
h = "f02390d55d92ff3ce11af0180ad4ea4a889a6a1acd9e5364d6cb67bd4d0dbe17"

#f02390d55d92ff3ce11af0180ad4ea4a889a6a1acd9e5364d6cb67bd4d0dbe17
#13 6
#f02390d55d92f63ce11af0180ad4ea4a889a6a1acd9e5364d6cb67bd4d0dbe17
#15 4
#f02390d55d92ff34e11af0180ad4ea4a889a6a1acd9e5364d6cb67bd4d0dbe17
#f02390d55d92f634e11af0180ad4ea4a889a6a1acd9e5364d6cb67bd4d0dbe17
#base64.urlsafe_b64encode(bytes.fromhex("f02390d55d92f634e11af0180ad4ea4a889a6a1acd9e5364d6cb67bd4d0dbe17"))

iv = '\x66' * 16

def main():
    for i in range(11,16):
        for x in list("0123456789abcdef"):
            r = remote('3.16.37.209', 3133)
            #r = process('./chall.sh'

            data = h[:i]+x+x+h[i+2:]

            r.sendlineafter('Ingresa tu llave:', base64.urlsafe_b64encode(bytes.fromhex(data)))
            r.recvline()

            try:
                msg = r.recvline().decode("utf-8")

                if 'Algo salio mal...' not in msg and '99' not in msg:
                    print(msg,end='')
                    print(i,x)
                    print(data)
                r.close()
            except Exception as e:
                pass

main()