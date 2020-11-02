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

# Meet in the middle attack.
#lines = open('./KPApairsDublin_non_linear.hex').readlines()
#lines = open('../KPAdataAtlanta/KPApairsAtlanta_non_linear.hex').readlines()

k1 = 0x1234
k2 = 0x5678

pairs = list()

for i in range(5):
    pla = np.random.randint(0, 2**16)
    md = u.enc(pla,k1,c)
    x = u.enc(md,k2,c)
    pairs.append((pla,x))

#for l in lines:
#    plaintx, ciphertx = tuple(l.split('\t'))
#    plaintx, ciphertx = int(plaintx, 16), int(ciphertx[:-1], 16)
#
#    pairs.append((plaintx, ciphertx))
#
#    #print("%x\t%x" % (plaintx, ciphertx))
#
#    #print("%x\t%x" % (u.enc(u.enc(plaintx, 0x1c50, c), 0x28c8, c), ciphertx))
#    #print("%x\t%x" % (u.enc(u.enc(plaintx, 0x6c19, c), 0x9c0c, c), ciphertx))

#pairs = pairs[2:]
candidates = None

for (plaintx, ciphertx) in pairs:
    fingerprint = str(plaintx) + str(ciphertx)

    if not os.path.exists(fingerprint + '.npy'):
        # Brute force the direct part first.
        def mma_direct(key):
            return u.enc(plaintx, key, c)

        with Pool(8) as p:
            direct_table = list(p.map(mma_direct, range(2**KEY_LEN)))

        direct_sort = np.argsort(direct_table)

        # Brute force the reverse part.
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

        # Cache the result..
        np.save(fingerprint, this_candidates)
    else:
        this_candidates = np.load(fingerprint + '.npy', allow_pickle=True).tolist()

    # Since this is a KPA attack all the pairs are encrypted
    # with the same key pair.
    if candidates is None:
        candidates = this_candidates
    else:
        candidates = candidates.intersection(this_candidates)

    if len(candidates) < 10:
        for (k1, k2) in candidates:
            print("k1:%x\tk2:%x"%(k1,k2))

    print('candidates: %d' % len(candidates))

for (k1, k2) in candidates:
    print("k1:%x\tk2:%x"%(k1,k2))
