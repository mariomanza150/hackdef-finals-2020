import socketserver
import base64
import random
import string
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from secreto import key

logo ='''
                CAJA FUERTE DE GRADO MILITAR
 
                   #REPUBLICA DE HACKDEF#

        Ejemplo de uso con su token en formato: 
         8COQ1V2S_zzhGvAYCtTqSoiaahrNnlNk1stnvU0Nvhc=
    
  Solo el administrador con el ID 01 tiene acceso a la informacion
   aqui contenida, toda la interaccion esta siendo monitoreada.
'''

with open("flag.txt") as f:
    flag = f.readline()

def decrypt_safe(iv, admin_token):
    try:
        ciphertext = base64.urlsafe_b64decode(admin_token)
        cipher = AES.new(bytes(key,"utf-8"), AES.MODE_CBC, bytes(iv,"utf-8"))
        decrypted_token = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return decrypted_token
    except:
        return b"Error!!!"

class Safe(socketserver.BaseRequestHandler):
    def handle(self):
        iv = '\x66' * 16
        self.request.send(bytes(logo,"utf-8"))
        while True:
            self.request.send(b"\r\nIngresa tu llave: ")
            key = self.request.recv(1024).strip()
            administrador_id = decrypt_safe(iv, key)
            print(administrador_id)
            if b"Error" in administrador_id :
                self.request.send(b"\r\nAlgo salio mal...")
                continue
            if administrador_id[22:24] == b"01":
                self.request.send(b"\r\nLlave de descifrado para la DB: ")
                self.request.send(bytes(flag,"utf-8"))
                break
            else:
                self.request.send(b"\r\nID incorrecto: %s, intente nuevamente..." % administrador_id[22:24])
                continue

if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 3102
    server = socketserver.ThreadingTCPServer((HOST, PORT), Safe)
    server.allow_reuse_address = True
    server.serve_forever()
