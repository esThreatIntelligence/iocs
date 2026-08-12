"""
Author: @YungBinary
Description: BinaryNinja script to decrypt strings in Cruciferra 
"""

import struct
import base64
import math
import re


def xor_data(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


MASK64 = 0xFFFFFFFFFFFFFFFF


def rol64(v, n):
    v &= MASK64
    n %= 64
    return ((v << n) | (v >> (64 - n))) & MASK64


def ror64(v, n):
    v &= MASK64
    n %= 64
    return ((v >> n) | (v << (64 - n))) & MASK64


# SHA-512 round constants
K0 = 0x428a2f98d728ae22 # k[0]
K1 = 0x7137449123ef65cd # k[1]
K2 = 0xb5c0fbcfec4d3b2f # k[2]

# 64-bit golden ratio multiplier used in SplitMix64
PHI = 0x9e3779b97f4a7c15

# State QWORDs dumped from rsi+0x10 (6 little-endian QWORDs)
STATE = [
    0xAD4E56D8C322E47E,  # rsi+0x10
    0x94E0B29192666474,  # rsi+0x18
    0x1BD2EF95DB966F28,  # rsi+0x20
    0x021E92D71D6357A0,  # rsi+0x28
    0x2021118A6BB6C1F4,  # rsi+0x30
    0xD5DC12F7F34A4F2E,  # rsi+0x38
]

# 6 total QWORDs
NUM_QWORDS = len(STATE)


def generate_keystream_block(state: list, counter: int) -> bytes:
    r14 = (counter ^ state[0] ^ K0) & MASK64
    r15 = (state[1] ^ ror64(counter, 0xb) ^ K1) & MASK64
    rbx = ((counter * PHI & MASK64) ^ state[2] ^ K2) & MASK64

    for r8 in range(8):
        r14_new = (rol64(rol64((r14 + r15) & MASK64, 5) ^ rbx, 7) + rbx) & MASK64

        # Modular indices into state array
        idx3 = (r8 + 3) % NUM_QWORDS
        idx4 = (r8 + 4) % NUM_QWORDS
        idx5 = (r8 + 5) % NUM_QWORDS

        rdx = ((r14_new ^ state[idx4]) + r15) & MASK64
        temp = (rol64(r14_new, 0x33) + state[idx3]) & MASK64
        r14_mix = (r14_new ^ rol64(temp ^ r15, 0x11)) & MASK64

        rbx = ((rol64(r14_mix, 0x3d) + rdx) & MASK64) ^ state[idx5]

        # Rotate state for next round
        r15 = r14_mix
        r14 = rdx

    out0 = (r14 ^ state[3]) & MASK64
    out1 = (r15 ^ state[4]) & MASK64
    out2 = (rbx ^ state[5]) & MASK64

    return struct.pack('<QQQ', out0, out1, out2)


def generate_keystream(state: list, num_blocks: int) -> bytes:
    """
    Generate num_blocks * 24 bytes of keystream.
    """
    return b''.join(generate_keystream_block(state, i) for i in range(num_blocks))


def contains_non_printable(data: bytes) -> bool:
    """
    Method for string validation post-decryption
    """
    return not all(0x20 <= b < 0x7f for b in data)

if __name__ == '__main__':

    # Find all System_String data variables and
    # extract the address of the data variable and string
    system_strings = [(addr, bv.get_comment_at(addr)[1:-1]) for addr, var in bv.data_vars.items() if 'System_String' in str(var.type)]

    # Filter for strings matching base64 regex
    # Note: not all matches are actually base64 encoded strings
    # so we check if the decrypted result later is printable
    b64_string_candidates = []
    for addr, comment in system_strings:
        if re.search(r'^[A-Za-z0-9+/=]{4,}$', comment):
            b64_string_candidates.append((addr, comment))

    # Iterate over the candidate base64 encrypted strings
    for addr, b64_candidate in b64_string_candidates:

        # Attempt to decode from base64
        try:
            ciphertext = base64.b64decode(b64_candidate)
        except:
            continue
        
        # Calculate the number of blocks needed by ceiling division
        num_blocks = math.ceil(len(ciphertext) / 24)

        # Generate the keystream
        xor_key = generate_keystream(STATE, num_blocks)

        # Decrypt the string
        plaintext = xor_data(ciphertext, xor_key)

        # Ignore strings that aren't in the printable ASCII range
        if contains_non_printable(plaintext):
            continue

        # Update the existing comment for the data variable
        print(f"Found encrypted string at: {hex(addr)}, encrypted: {b64_candidate}, decrypted: {plaintext}")
        plaintext = plaintext.decode()
        bv.set_comment_at(addr, f"{b64_candidate}, decrypted: {plaintext}")

        # Find where the variable is referenced and add a comment
        ref_addrs = [ref.address for ref in bv.get_code_refs(addr)]
        for ref_addr in ref_addrs:
            # Skip already commented addresses
            if ref_addr == addr:
                continue
            bv.set_comment_at(ref_addr, plaintext)
