import f_cipher as ciph

cipher = ciph.Feistel(32, 17, 0x80000000)

x = cipher.encryption(0x80000000)

print("The messsage x = " + str(hex(x)))

u = cipher.decryption(x)

print("The messsage u = " + str(hex(u)))