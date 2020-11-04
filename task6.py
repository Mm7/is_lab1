import utils as u
import numpy as np
import sys

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

def linearized_round_func(y, rk):
    w = u.BitArray(MSG_LEN)

    # First half of the block.
    for j in range(1, L//2 + 1):
        w[j] = y[j] ^ rk[4*j-3]

    # Second half of the block.
    for j in range(L//2 + 1, L + 1):
        w[j] = y[j] ^ rk[4*j-2*L]

    return w

# Compute `Mv` where `M` is a matrix and `v` is a plain/cipher text.
def matmul(M, v):
    r = u.BitArray(MSG_LEN)

    for i in range(1, MSG_LEN + 1):
        p = M[i-1].to_int() & v
        r[i] = bin(p).count('1') % 2

    return r.to_int()

# Convert a matrix to the numpy format.
def to_numpy(M):
    np_M = np.zeros((MSG_LEN, MSG_LEN))

    for i in range(1,MSG_LEN + 1):
        for j in range(1, MSG_LEN + 1):
            np_M[i-1][j-1] = M[i-1][j]

    return np_M

# Convert back from numpy format.
def from_numpy(np_M):
    M = [u.BitArray(MSG_LEN) for _ in range(MSG_LEN)]

    for i in range(1,MSG_LEN + 1):
        for j in range(1, MSG_LEN + 1):
            M[i-1][j] = int(np_M[i-1][j-1])

    return M

# Invert a binary matrix.
def matinv(M):
    np_M = to_numpy(M)

    inv_real = np.linalg.inv(np_M)
    det_real = np.linalg.det(np_M)

    inv_bin = np.round(inv_real * det_real) % 2

    return from_numpy(inv_bin)

# Guess the key given a plaintext,ciphertext pair.
def key_guess(A_inv, B, x, u):
    return matmul(A_inv, x ^ matmul(B, u))

# Compute the A, B matrices for the linearized cipher.
c = u.Cipher(MSG_LEN, KEY_LEN, ROUNDS, linearized_round_func, subkey)

A = [u.BitArray(MSG_LEN) for _ in range(MSG_LEN)]
B = [u.BitArray(MSG_LEN) for _ in range(MSG_LEN)]
for i in range(1, MSG_LEN + 1):
    for j in range(1, MSG_LEN + 1):
        e_j = 1 << (MSG_LEN-j)

        A[i-1][j] = u.BitArray(MSG_LEN, u.enc(0, e_j, c))[i]
        B[i-1][j] = u.BitArray(MSG_LEN, u.enc(e_j, 0, c))[i]

A_inv = matinv(A)

# Now try to break the non-linear cipher.
c = u.Cipher(MSG_LEN, KEY_LEN, ROUNDS, round_func, subkey)

# Load the test pairs.
lines = open('KPApairsDublin_nearly_linear.hex').readlines()
pairs = list()

for l in lines:
    plaintx, ciphertx = tuple(l.split('\t'))
    plaintx, ciphertx = int(plaintx, 16), int(ciphertx[:-1], 16)

    pairs.append((plaintx, ciphertx))

# Try to find the encryption key.
success = False
for plaintx, ciphertx in pairs:
    guessed_key = key_guess(A_inv, B, ciphertx, plaintx)

    re_cipher = u.enc(plaintx, guessed_key, c)

    if re_cipher == ciphertx:
        print('Key found: %x!' % guessed_key)
        success = True
        break

if not success:
    print('Key not found :(')
    sys.exit(1)

# Verify that the recovered key works with all the pairs!
success = True
for plaintx, ciphertx in pairs:
    re_cipher = u.enc(plaintx, guessed_key, c)
    if re_cipher != ciphertx:
        success = False

if success:
    print('The guessed key works correctly for all the pairs')
else:
    print('The key seems to work only for some pairs')

# Now, let's estimate the success probability of the linear approximation used.
#
# Considering the first l/2 bits, the round function is:
#    w[j] = y[j] ^ (rk[4*j-3] & (y[2*j-1] | rk[2*j-1] | rk[2*j] | rk[4*j-2]))
#
# If any of the ORed terms is true, then w[j] is equal to:
#    w[j] = y[j] ^ rk[4*j-3]
#
# Now, let's run a simulation to estimate the probability that this approximations holds:
total_cases = 5000
success_cases = 0

for _ in range(total_cases):
    # Generate a random key.
    k = u.BitArray(KEY_LEN, np.random.randint(0, 2**KEY_LEN))

    # Simulate all the rounds of the cipher and check if the
    # linear approximation holds for all of them.
    holds = True

    for i in range(1, ROUNDS + 1):
        # Compute the round key.
        rk = subkey(k, i)

        # Compare the linear approx. to the ground-truth.
        for j in range(1, L//2 + 1):
            if rk[4*j-3] != (rk[4*j-3] & (rk[2*j-1] | rk[2*j] | rk[4*j-2])):
                holds = False
                break

        for j in range(L//2 + 1, L + 1):
            if rk[4*j-2*L] != (rk[4*j-2*L] & (rk[2*j-1] | rk[2*j] | rk[4*j-2*L-1])):
                holds = False
                break

    # If it holds, increment the success counter
    if holds:
        success_cases += 1

# Fraction of success (~probability of success).
prob_succ = success_cases / total_cases

print('Success probability: %.2e' % prob_succ)
print('Random guess probability: %.2e' % (1/(2**MSG_LEN)))

