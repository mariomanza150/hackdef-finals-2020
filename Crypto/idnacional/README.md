# ID Nacional

### Resuelto por Manjaro

### Descripcion del Reto

Este reto nos pedia decodificar un archivo para sacar la *id* de una credencial contenida en *ID_Encrypted* y nos proporcionaron el archivo de la llave publica *certificado.pub*, con un poco de codigo podemos sacar los datos de la llave publica.

```python
from Crypto.PublicKey import RSA

key = RSA.importKey(open('certificado.pub').read())
print(key.n,"\n",key.e)
```

y nos muestra **n = 18634177033470544580810...** y **e = 3**

### Solucion

Este RSA tenia la "falla" de que su exponente de encriptacion **e** era muy pequeño, pudiendo asi sacar el *plaintext* **p** con ```p = cipher^1/3```, suponiendo que se cumple la condicion de ```p^e < n``` y que la raiz sea exacta.

Pero como en este reto no es el caso, tendremos que sumarle multiplos de **n** a nuestro *ciphertext* **c** para que se cumpla la condicional. Asi usamos este script derivado de esta pagina [rsa_e_attack](https://ctf-wiki.github.io/ctf-wiki/crypto/asymmetric/rsa/rsa_e_attack/)

```python
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
```

y nos muestra el nombre y id de la credencial:
FLAG -> b'RUTILIO SOBERANO\nID: 983348933400987\n'
