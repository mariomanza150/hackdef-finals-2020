# Xtreme

### Descripcion del Reto

En este reto nos dieron un *exe* **XtremeTool.exe** y un *archivo encriptado* **DB_Password** con ese ejecutable. Al descompilar y analizarlo, nos topamos con las 2 cosas que nos permitieron resolver este reto.

La llave de encripcion y el algortimo con el que se encripto.
**adde0000efbe0000beba0000cefa0000**
**XTEA** (Extended Tiny Encryption Algorithm)

### Solucion

Apartir de eso fue simple, desencriptar el archivo con alguna implementacion del algoritmo.
Al probar con algunas, encriptando un archivo propio y comprobando que la implementacion lo pudiera desencriptar con la llave, dimos con este script: [Script](https://asecuritysite.com/encryption/xtea)

Modificandolo un poco y guardando el resultado en un archivo de texto nos dimos cuenta de que era un pdf.

```python
key="adde0000efbe0000beba0000cefa0000"

x = XTEA()

with open("DB_Password", "rb") as f: 
    for i in range(500):
        txt = open("out.txt", "ab")
        message = f.read(8)
        key = key.rjust(32, '0')      # Key is 32 hex chars - 128 bits 
        message = message.rjust(8, b'0')  # Block size is 64 bytes
        r = x.xtea_decrypt(bytes.fromhex(key),message)
        txt.write(r)
        txt.close()```

Cambiando la extension y abriendolo nos dio la flag.

![Solve](solve.pdf)