import base64
from itertools import cycle, product
import string

# The given encoded string
encoded_str = "JR4YFw8YLwA7Jx0mCRsaGBsMKhwSLwMdLhsBMC0YHBgwMwcBMBcmFBsfIjAHKxMVHBEBIAoXfA8="

# Decoding the string using Base64
decoded_bytes = base64.b64decode(encoded_str)

# Function to perform multi-byte XOR decryption
def xor_multi_byte(data, key):
    return bytes([b ^ k for b, k in zip(data, cycle(key))])

# Known flag format
known_prefix = b"flag{"
known_suffix = b"}"

# Find first 5 bytes of key based on known prefix
key = bytearray()
for i in range(len(known_prefix)):
    # Try each possible byte value
    for candidate in map(ord, string.printable):
        trial_key = key + bytearray([candidate])
        decrypted = xor_multi_byte(decoded_bytes[:len(trial_key)], trial_key)
        
        # Check if decryption matches known prefix
        if decrypted.startswith(known_prefix[:len(trial_key)]):
            key.append(candidate)
            print(f"Found key byte {i+1}: {hex(candidate)} ('{chr(candidate)}')")
            break

print(f"First 5 bytes of key found: {bytes(key)}")

key = b'Crypto'
for i in range(len(decoded_bytes)):
    decrypted = xor_multi_byte(decoded_bytes[i:], key)
    if all(chr(b) in string.printable for b in decrypted[i:]):
        print(i)
        print(decrypted)

# key length is 9

# Use CyberChef to retrieve the key CryptoGod

# flag{who_do_you_think_writes_all_these_dope_challenges?}
