from collections import namedtuple

# Helper class which provides easy bit-level operations over numbers.
class BitArray():
    def __init__(self, size, num=0):
        self.size = size
        self.arr = [((num >> i) & 1) for i in range(size)]

    def __getitem__(self, index):
        assert index > 0
        assert index <= self.size

        return self.arr[self.size-index]

    def __setitem__(self, index, value):
        assert value == 0 or value == 1
        assert index > 0
        assert index <= self.size

        self.arr[self.size-index] = value

    def __xor__(self, other):
        res = BitArray(self.size)

        for j in range(1, self.size + 1):
            res[j] = self[j] ^ other[j]

        return res

    # Split this bit array into two smaller bit arrays.
    def split(self):
        upper = BitArray(self.size)
        lower = BitArray(self.size)

        lower.arr[self.size // 2:] = self.arr[:self.size // 2]
        upper.arr[self.size // 2:] = self.arr[self.size // 2:]

        return upper, lower

    # Join this bit array to `other`.
    def join(self, other):
        res = BitArray(self.size)

        res.arr[:self.size // 2] = self.arr[self.size // 2:]
        res.arr[self.size // 2:] = other.arr[self.size // 2:]

        return res

    # Convert a bit array to an integer.
    def to_int(self):
        i = 0

        for j in range(self.size):
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

    k = BitArray(c.key_len, k)
    l = c.msg_len // 2

    # Split the input message into 2 `l` bit long blocks (`z_1` and `y_1` in the
    # scheme).
    y, z = BitArray(c.msg_len, u).split()

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

# Decrypt a ciphertext.
#
# Parameters:
#   `x`: input ciphertext to decrypt. The size of this ciphertext in bits is `msg_len`.
#   `k`: encryption key.
#   `c`: Feistel cipher to use for the encryption.
def dec(x, k, c):
    assert isinstance(c, Cipher)

    k = BitArray(c.key_len, k)
    l = c.msg_len // 2

    # Split the input ciphertext into 2 `l` bit long blocks (`z_1` and `y_1` in the
    # scheme).
    y, v = BitArray(c.msg_len, x).split()

    for i in reversed(range(1, c.rounds + 1)):
        # Generate the round key.
        round_key = c.subkey_func(k, i)

        # S
        w = c.round_func(y, round_key)

        # L
        z = v ^ w

        # In the final round the transposition is skipped.
        if i != 1:
            # T
            v = y
            y = z

    # Join the `z` and `y` blocks to make the message text.
    x = z.join(y).to_int()

    return x


# Decrypt a ciphertext `x` by inverting the round key sequence.
#
# This function can be used to verify the correctness of the implementation
# of the Feistel cipher.
#
# The implementation simply reuses `enc` with the subkey generated
# in the reverse order.
def inv_enc(x, k, c):
    def inv_subkey_func(k,i):
        return c.subkey_func(k, c.rounds - i + 1)

    # Create a new cipher identical to `c` except for the subkey generation function.
    # The new one is simply a wrapper over the old one which reverses the round number.
    new_c = Cipher(c.msg_len, c.key_len, c.rounds, c.round_func, inv_subkey_func)

    return enc(x, k, new_c)

