import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def encrypt_db(key, inf, outf):
    with open(inf, "rb") as f:
        data = f.read()
        f.close()
    cipher = AES.new(bytes(key,"utf-8"),AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(pad(data,AES.block_size))

    with open(outf, "wb") as o:
        [o.write(x) for x in (cipher.nonce, tag, ciphertext)]
        o.close

    print("[*] Archivo cifrado correctamente!")

def decrypt_db(key, inf, outf):
    e = open(inf, "rb")
    nonce, tag, ciphertext = [e.read(x) for x in (16,16,-1)]

    cipher = AES.new(bytes(key,"utf-8"), AES.MODE_EAX, nonce)
    data = unpad(cipher.decrypt_and_verify(ciphertext, tag), AES.block_size)

    with open(outf,"w") as of:
        of.write(data.decode("utf-8"))
        of.close()

if __name__ == '__main__':
    """if len(sys.argv) < 4:
        print("[-] Uso: <encrypt/decrypt> <llave> <ruta archivo de entrada> <ruta archivo de salida> ")
        sys.exit(6)"""
    mode = "decrypt"
    key = "_!h4ckD3fs3kr3T@"
    input_file = "database_export.bin"
    output_file = "db.txt"
    if "encrypt" in mode:
        encrypt_db(key, input_file, output_file)
        sys.exit(0)
    elif "decrypt" in mode:
        decrypt_db(key, input_file, output_file)
        sys.exit(0)
    else:
        print("[!] Opcion no soportada!")
        sys.exit(6)
