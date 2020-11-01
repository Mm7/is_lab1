import f_cipher as ciph
import lin_attack as lin


cipher = ciph.Feistel(32, 17, 0x80000000)


sys_solv = lin.Linear_Attack(32, 32, 32)

#Matrices A and B that represent the Feistel Cipher 
A = sys_solv.round_mat(sys_solv.find_A_matrix(17))
B = sys_solv.round_mat(sys_solv.find_B_matrix(17))

xi = cipher.encryption(0x80000000)
ui = cipher.decryption(xi)
key = sys_solv.extract_key(17,xi, ui)


print("The actua key : " + str(hex(0x80000000)))
print("The key : " + str(hex(key)))
print("The messsage u = " + str(hex(ui)))
print("The orginal x = " + str(hex(xi)))

cipher = ciph.Feistel(32, 17, key)
xi = cipher.encryption(ui)
print("Obtained x using the encryption with the key found  = " + str(hex(xi)))
print("||||||||||||||||||||||||||||")

u_message1 = 0x95D41B79
x_message1 = 0x9C62091D


key1 = sys_solv.extract_key(17, x_message1, u_message1)

print("The key : " + str(hex(key1)))

cipher = ciph.Feistel(32, 17, key1)
xi1 = cipher.encryption(u_message1)
ui1 = cipher.decryption(xi1)
print("The original mex : " + str(hex(ui1)))
print("USING THE CIPHER : ")
print("The real x : " + str(hex(x_message1)))
print("Obtained x using the encryption with the key found : " + str(hex(xi1)))

u_message1 = sys_solv.round_vec(sys_solv.vectorize_bits(u_message1, 32))
key1 = sys_solv.round_vec(sys_solv.vectorize_bits(key1, 32))

x = sys_solv.vec_sum( sys_solv.mat_vec_prod(A, key1), sys_solv.mat_vec_prod(B, u_message1))

print("USING THE LINEAR SYSTEM : ")
print("Obtained x using the encryption with the key found  : " + str(hex(sys_solv.bitization(x))))
