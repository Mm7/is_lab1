import utils as u

# Configure the cipher.
L = 16
MSG_LEN = L*2
KEY_LEN = 32
ROUNDS = 5

def subkey(k, i):
    round_key = u.BitArray(KEY_LEN)

    for j in range(1, KEY_LEN + 1):
        round_key[j] = k[((5*i+j-1) % KEY_LEN) + 1]

    return round_key

def round_func(y, rk):
    w = u.BitArray(L)

    # First half of the block.
    for j in range(1, L//2 + 1):
        w[j] = y[j] ^ (rk[4*j-3] & (y[2*j-1] | rk[2*j-1] | rk[2*j] | rk[4*j-2]))

    # Second half of the block.
    for j in range(L//2 + 1, L + 1):
        w[j] = y[j] ^ (rk[4*j-2*L] & (y[2*j-L] | rk[2*j-1] | rk[2*j] | rk[4*j-2*L-1]))

    return w

c = u.Cipher(MSG_LEN, KEY_LEN, ROUNDS, round_func, subkey)

e = u.enc(0x12345678, 0x87654321, c)
print("ciphertext --> %x" % e)
d = u.dec(e, 0x87654321, c)
print("decrypted message --> %x" % d)



