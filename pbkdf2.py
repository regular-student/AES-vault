import hashlib
import os

def gerar_chave_pbkdf2(senha_texto, salt_bytes=None):
    #transforma a senha em uma chave AES-256 de 32 bytes
    senha_bytes = senha_texto.encode('UTF-8')

    # -> senha nova - salt novo <-
    if salt_bytes is None:
        salt_bytes = os.urandom(16)

    #pbkdf2_hmac(algoritmo, senha, salt, iterações, tamanho_desejado)
    chave_32_bytes = hashlib.pbkdf2_hmac(
        'sha256',      #algoritmo de hash base
        senha_bytes,   #senha do usuário
        salt_bytes,    #O salt aleatório
        100000,        #numero de iterações
        dklen=32       #32 bytes pro AES-256
    )

    return chave_32_bytes, salt_bytes
    
