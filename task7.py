import f_non_linear as ciph



cipher = ciph.Feistel(16, 13, 0x369C)

u = 0x0
x = cipher.encryption(u)

print(hex(x))
