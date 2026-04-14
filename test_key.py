from key_expansion import key_expansion

def run_test():
    # boil plate code -> testa o key_expansion

    #vetor de teste oficial 
    chave_nist = bytes([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    ])

    resultados_esperados = {
        8:  [0xa5, 0x73, 0xc2, 0x9f], #testa RotWord + SubWord + Rcon[1]
        9:  [0xa1, 0x76, 0xc4, 0x98], #testa XOR simples com w[1]
        10: [0xa9, 0x7f, 0xce, 0x93], #testa XOR simples com w[2]
        11: [0xa5, 0x72, 0xc0, 0x9c], #testa XOR simples com w[3]
        12: [0x16, 0x51, 0xa8, 0xcd], #testa Regra especial do AES-256 (apenas SubWord, sem RotWord/Rcon)
        59: [0x6d, 0x68, 0xde, 0x36]  #testa A última palavra (w[59]) de toda a expansão
    }

    w = key_expansion(chave_nist)

    print("Validação da key_expansion (AES-256) •••\n")

    if len(w) != 60: return "Length error"

    sucesso = True

    for indice, valor_esperado in resultados_esperados.items():
        valor_obtido = w[indice]

        hex_esperado = [hex(b) for b in valor_esperado]
        hex_obtido = [hex(b) for b in valor_obtido]

        if valor_obtido == valor_esperado:
            print(f"w[{indice}]: Correto! -> {hex_obtido}")
        else:
            print(f"w[{indice}]: Incorreto!")
            print(f"   Esperado: {hex_esperado}")
            print(f"   Obtido:   {hex_obtido}")
            sucesso = False

    if sucesso == False: print("Há algo de errado.")

if __name__ == "__main__":
    run_test()    
