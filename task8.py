import utils as u
import numpy as np
from multiprocessing import Pool
import sys
import os.path

# Configure the cipher.
L = 8
MSG_LEN = L*2
KEY_LEN = 16
ROUNDS = 13

def subkey(k, i):
    round_key = u.BitArray(KEY_LEN)

    for j in range(1, KEY_LEN + 1):
        round_key[j] = k[((5*i+j-1) % KEY_LEN) + 1]

    return round_key

def round_func(y, rk):
    w = u.BitArray(MSG_LEN)

    # First half of the block.
    for j in range(1, L//2 + 1):
        w[j] = (y[j] & rk[2*j-1]) | (y[2*j-1] & rk[2*j]) | rk[4*j]

    # Second half of the block.
    for j in range(L//2 + 1, L + 1):
        w[j] = (y[j] & rk[2*j-1]) | (rk[4*j-2*L-1] & rk[2*j]) | y[2*j-L]

    return w

c = u.Cipher(MSG_LEN, KEY_LEN, ROUNDS, round_func, subkey)

#### Meet in the middle attack.

# Import the plaintext/ciphertext pairs.
lines = open('./KPApairsDublin_non_linear.hex').readlines()
pairs = list()

for l in lines:
    plaintx, ciphertx = tuple(l.split('\t'))
    plaintx, ciphertx = int(plaintx, 16), int(ciphertx[:-1], 16)

    pairs.append((plaintx, ciphertx))

# List of candidate key pairs.
candidates = None

for (plaintx, ciphertx) in pairs:
    # Brute force the direct part (plaintext -> middle).
    def mma_direct(key):
        return u.enc(plaintx, key, c)

    with Pool(8) as p:
        direct_table = list(p.map(mma_direct, range(2**KEY_LEN)))

    direct_sort = np.argsort(direct_table)

    # Brute force the reverse part (middle <- ciphertext).
    def mma_inverse(key):
        return u.dec(ciphertx, key, c)

    with Pool(8) as p:
        inverse_table = list(p.map(mma_inverse, range(2**KEY_LEN)))

    inverse_sort = np.argsort(inverse_table)

    # Look for candidate key pairs..
    i = 0
    j = 0

    this_candidates = set()
    while i < 2**KEY_LEN and j < 2**KEY_LEN:
        if direct_table[direct_sort[i]] == inverse_table[inverse_sort[j]]:
            k = j
            while k < 2**KEY_LEN and direct_table[direct_sort[i]] == inverse_table[inverse_sort[k]]:
                this_candidates.add((direct_sort[i], inverse_sort[k]))
                k += 1

            i += 1
        elif direct_table[direct_sort[i]] > inverse_table[inverse_sort[j]]:
            j += 1
        else:
            i += 1

    # Since this is a KPA attack all the pairs are encrypted
    # with the same key pair.
    if candidates is None:
        candidates = this_candidates
    else:
        candidates = candidates.intersection(this_candidates)

    print('Size of the pool of candidates key pairs: %d' % len(candidates))

print('Attack completed. Printing the candidates key pairs:')
for (k1, k2) in candidates:
    print("\tk1:0x%x\tk2:0x%x"%(k1,k2))
