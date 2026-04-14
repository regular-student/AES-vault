from utils import rot_word, sub_word, rcon

def key_expansion(chave_bytes):
    #chave_bytes: 32 bytes
    #retorna 60 palavras 

    #nesse passo ele vai dividir a chave em 8 palavras
    w = []

    for i in range(0, 32, 4):
        w.append(list(chave_bytes[i:i+4]))

    #nesse passo ele expande pra 60 palavras
    for i in range(8, 60):
        temp = w[-1][:] #copia a palavra anterior

        if i % 8 == 0:
            #aplica a transformação
            temp = rot_word(temp)
            temp = sub_word(temp)
            temp[0] ^= rcon[i // 8]
        elif i % 8 == 4:
            #aplica subword
            temp = sub_word(temp)

        #xor com palavra de 8 posições atrás
        nova_palavra = []
        for j in range(4):
            nova_palavra.append(w[i - 8][j] ^ temp[j])

        w.append(nova_palavra)


    return w
        
    
