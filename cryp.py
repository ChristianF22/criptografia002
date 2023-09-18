import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

#RECEBE A MENSAGEM A SER ENVIADA
msn = input("Digite sua mensagem: ")
hash_object = hashlib.sha256()
hash_object.update(msn.encode('utf-8'))
hash_hex = hash_object.hexdigest()

#PREPARANDO A CRIPTOGRAFIA
#msn = msn.upper()
key = os.urandom(32)
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
msn_bytes = msn.encode('utf-8')
padder = padding.PKCS7(128).padder()
msn_bytes_padded = padder.update(msn_bytes) + padder.finalize()

#ENCRIPTOGRAFANDO A MENSAGEM
encryptor = cipher.encryptor()
ciphertext = encryptor.update(msn_bytes_padded) + encryptor.finalize()
print(ciphertext)