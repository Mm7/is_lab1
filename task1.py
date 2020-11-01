import f_cipher_enc as enc

cipher = enc.Feistel_Encr(32, 17, 0x80000000)

print(hex(cipher.encryption(0x80000000)))