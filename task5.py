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
    w = u.BitArray(MSG_LEN)

    # First half of the block.
    for j in range(1, L//2 + 1):
        w[j] = y[j] ^ (rk[4*j-3] & (y[2*j-1] | rk[2*j-1] | rk[2*j] | rk[4*j-2]))

    # Second half of the block.
    for j in range(L//2 + 1, L + 1):
        w[j] = y[j] ^ (rk[4*j-2*L] & (y[2*j-L] | rk[2*j-1] | rk[2*j] | rk[4*j-2*L-1]))

    return w

c = u.Cipher(MSG_LEN, KEY_LEN, ROUNDS, round_func, subkey)

# Verify the correctness of the implementation of the cipher.
plaintext = 0x12345678
key = 0x87654321
e = u.enc(plaintext, key, c)
print("ciphertext --> 0x%x" % e)
d = u.dec(e, key, c)
print("decrypted message --> 0x%x" % d)

assert plaintext == d
assert plaintext == u.inv_enc(e, key, c)

