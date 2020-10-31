import utils as u

# Configure the cipher.
L = 16
MSG_LEN = L*2
KEY_LEN = 32
ROUNDS = 17

def subkey(k, i):
    round_key = 0

    for j in range(KEY_LEN):
        # Compute the jth bit of the round key. The formula is
        # adjusted to a 0-based range.
        k_index = (5*(i+1)+(j+1)-1) % KEY_LEN
        assert k_index >= 0 and k_index < KEY_LEN
        j_bit = (k >> k_index) & 1

        # Copy the bit to the round key.
        round_key |= (j_bit << j)

    return round_key

def round_func(y, rk):
    w = 0

    # First half of the block.
    for j in range(L//2):
        # Compute the jth bit of the block. The formula is adjusted
        # to a 0-based range.
        k_index = 4*(j+1)-3-1
        assert k_index >= 0 and k_index < KEY_LEN
        j_bit = ((y >> j) & 1) ^ ((rk >> k_index) & 1)

        # Copy the bit to the block.
        w |= (j_bit << j)

    # Second half of the block.
    for j in range(L//2, L):
        k_index = 4*(j+1)-2*L-1
        assert k_index >= 0 and k_index < KEY_LEN
        j_bit = ((y >> j) & 1) ^ ((rk >> k_index) & 1)

        w |= (j_bit << j)

    return w

c = u.Cipher(MSG_LEN, KEY_LEN, ROUNDS, round_func, subkey)

e = u.enc(0x80000000, 0x80000000, c)
print("ciphertext --> %x" % e)
d = u.dec(e, 0x80000000, c)
print("decrypted message --> %x" % d)



