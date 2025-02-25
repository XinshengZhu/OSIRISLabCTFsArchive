import base64

# The given encoded string
encoded_str = "IConIT0xdSoldit1GTJ2GTIudRkxdigidTQgMyoZMXY0KiIZdiAZJTQ/NjJ2Zzs="

# Decoding the string using Base64
decoded_bytes = base64.b64decode(encoded_str)

# Converting the bytes to a hex representation for better inspection
decoded_hex = decoded_bytes.hex()

# Output the decoded bytes
print(decoded_bytes)

# Trying XOR decryption with single-byte keys
def xor_single_byte(data, key):
    return bytes([b ^ key for b in data])

# Attempt brute force with all possible single-byte keys (0x00 to 0xFF)
for key in range(256):
    result = xor_single_byte(decoded_bytes, key)
    if b"flag" in result:
        print(f"Key: {key}, Result: {result}")
        break

# flag{w3lc0m3_t0_th3_w0nd3rful_w0rld_0f_crypt0!}
