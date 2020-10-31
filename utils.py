import copy
from collections import namedtuple

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

# Generate a bit mask (i.e. a sequence of 1 bit).
# For example: mask(1) returns 0x1 (0b1),
#              mask(2) returns 0x3 (0b11),
#              mask(3) returns 0x7 (0b111),
#              mask(4) returns 0xf (0b1111),
def mask(s):
    return (1 << s) - 1

# Encrypt a message.
#
# Parameters:
#   `u`: input message to encrypt. The size of this message in bits is `msg_len`.
#   `k`: encryption key.
#   `c`: Feistel cipher to use for the encryption.
def enc(u, k, c):
    # Sanity checks...
    assert u & ~mask(c.msg_len) == 0
    assert k & ~mask(c.key_len) == 0
    assert isinstance(c, Cipher)

    l = c.msg_len // 2

    # Split the input message into 2 `l` bit long blocks (`z_1` and `y_1` in the
    # scheme).
    z = u & mask(l)
    y = u >> l

    print("round\tz\ty\tv")
    for i in range(c.rounds):
        # Generate the round key.
        round_key = c.subkey_func(k, i)
        assert round_key & ~mask(c.key_len) == 0

        # S
        w = c.round_func(y, round_key)
        assert w & ~mask(l) == 0

        # L
        v = z ^ w
        assert v & ~mask(l) == 0

        # In the final round the transposition is skipped.
        if i < c.rounds - 1:
            # T
            z = y
            y = v

        print("%d\t%x\t%x\t%x" % (i, z, y, v))

    # Join the `v` and `y` blocks to make the cipher text.
    x = v | (y << l)
    assert x & ~mask(c.msg_len) == 0

    return x

# Decrypt a ciphertext `x`.
# All the parameters are the same as `enc` (except for the ciphertext `x`).
#
# The implementation simply reuses `enc` with the subkey generated
# in the reverse order.
def dec(x, k, c):
    def inv_subkey_func(k,i):
        return c.subkey_func(k, c.rounds - i - 1)

    # Create a new cipher identical to `c` except for the subkey generation function.
    # The new one is simply a wrapper over the old one which reverses the round number.
    new_c = Cipher(c.msg_len, c.key_len, c.rounds, c.round_func, inv_subkey_func)

    return enc(x, k, new_c)

