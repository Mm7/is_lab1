from collections import namedtuple

class BitArray():
    def __init__(self, num=0):
        self.arr = [((num >> i) & 1) for i in range(32)]

    def __getitem__(self, index):
        assert index > 0
        assert index <= 32

        return self.arr[32-index]

    def __setitem__(self, index, value):
        assert value == 0 or value == 1
        assert index > 0
        assert index <= 32

        self.arr[32-index] = value

    def __xor__(self, other):
        res = BitArray()

        for j in range(1, 32 + 1):
            res[j] = self[j] ^ other[j]

        return res

    # Split this bit array into two smaller bit arrays.
    def split(self):
        upper = BitArray()
        lower = BitArray()

        lower.arr[16:] = self.arr[:16]
        upper.arr[16:] = self.arr[16:]

        return upper, lower

    # Join this bit array to `other`.
    def join(self, other):
        res = BitArray()

        res.arr[:16] = self.arr[16:]
        res.arr[16:] = other.arr[16:]

        return res

    # Convert a bit array to an integer.
    def to_int(self):
        i = 0

        for j in range(32):
            i |= (self.arr[j] << j)

        return i

# This tuple stores the parameters of a Feistel cipher.
#   `msg_len`: size of the message (which is the same as the cipher text) in bit.
#   `key_len`: size of the key in bit.
#   `rounds`: number of rounds.
#   `round_func`: round function. Takes as parameters: [`blk`: a `l` bit long block called `y`
#        in the scheme, `k`: a `key_len` bit long key specific to this round] and
#        returns a `l` bit long block (`w` in the scheme).
#   `subkey_func`: key derivation function. Given the encryption key and the round number,
#        returns the round key. Takes as parameters [`k`: encryption key, `i`: round
#        number] and returns the round key.
Cipher = namedtuple('Cipher', ['msg_len', 'key_len', 'rounds', 'round_func', 'subkey_func'])

# Encrypt a message.
#
# Parameters:
#   `u`: input message to encrypt. The size of this message in bits is `msg_len`.
#   `k`: encryption key.
#   `c`: Feistel cipher to use for the encryption.
def enc(u, k, c):
    assert isinstance(c, Cipher)

    k = BitArray(k)
    l = c.msg_len // 2

    # Split the input message into 2 `l` bit long blocks (`z_1` and `y_1` in the
    # scheme).
    y, z = BitArray(u).split()

    for i in range(1, c.rounds + 1):
        # Generate the round key.
        round_key = c.subkey_func(k, i)

        # S
        w = c.round_func(y, round_key)

        # L
        v = z ^ w

        # In the final round the transposition is skipped.
        if i < c.rounds:
            # T
            z = y
            y = v

    # Join the `v` and `y` blocks to make the cipher text.
    x = v.join(y).to_int()

    return x

# Decrypt a ciphertext `x`.
# All the parameters are the same as `enc` (except for the ciphertext `x`).
#
# The implementation simply reuses `enc` with the subkey generated
# in the reverse order.
def dec(x, k, c):
    def inv_subkey_func(k,i):
        return c.subkey_func(k, c.rounds - i + 1)

    # Create a new cipher identical to `c` except for the subkey generation function.
    # The new one is simply a wrapper over the old one which reverses the round number.
    new_c = Cipher(c.msg_len, c.key_len, c.rounds, c.round_func, inv_subkey_func)

    return enc(x, k, new_c)

