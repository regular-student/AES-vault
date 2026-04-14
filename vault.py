import sys
import os 
from getpass import getpass # Importante para ler a senha sem exibir no terminal
from pbkdf2 import gerar_chave_pbkdf2
from aes import encrypt_cbc, decrypt_cbc
from test_key import run_test

def cifrar_arquivo(caminho, senha):
    #gerar a chave e IV
    chave, salt = gerar_chave_pbkdf2(senha)
    iv = os.urandom(16)

    #ler o cont do arquivo
    with open(caminho, 'rb') as file:
        dados = file.read()

    ciphertext = encrypt_cbc(dados, chave, iv)

    #salvar
    with open(caminho + ".cifrado", "wb") as file:
        file.write(salt)
        file.write(iv)
        file.write(ciphertext)
    print(f"Arquivo cifrado: {caminho}")

def decifrar_arquivo(caminho, senha):
    with open(caminho, "rb") as file:
        conteudo = file.read()

    #Extrair metadados
    salt = conteudo[:16]
    iv = conteudo[16:32]
    ciphertext = conteudo[32:]

    #derivar chave com o salt
    chave, _ = gerar_chave_pbkdf2(senha, salt_bytes=salt)

    try:
        original = decrypt_cbc(ciphertext, chave, iv)
        print("\nConteúdo original:")
        print(original.decode('utf-8'))
    except Exception as e:
        print("Erro: Senha incorreta ou arquivo corrompido.")

def main():
    if len(sys.argv) < 2:
        print("Uso: python vault.py [cifrar/decifrar/testar] [arquivo]")
        return

    comando = sys.argv[1]

    if comando == "cifrar" and len(sys.argv) > 2:
        arquivo = sys.argv[2]
        senha = getpass("Digite a senha para cifrar: ")
        cifrar_arquivo(arquivo, senha)

    elif comando == "decifrar" and len(sys.argv) > 2:
        arquivo = sys.argv[2]
        senha = getpass("Digite a senha para decifrar: ")
        decifrar_arquivo(arquivo, senha)

    elif comando == "testar":
        print("Executando testes NIST...")
        run_test() #chama o teste que valida a Key Expansion

    else:
        print("Comando inválido ou falta o nome do arquivo.")

if __name__ == "__main__":
    main()
    
