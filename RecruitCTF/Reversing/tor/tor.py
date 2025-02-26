def reverse_transform(s):
    # ROT13 reverse
    result = ""
    for c in s:
        # Subtract 13 from each character
        new_char = ord(c) - 13
        
        # If we went below 'a', wrap around
        if new_char < ord('a'):
            new_char += 26
            
        result += chr(new_char)
    return result

target = "onolerirefvat"
answer = reverse_transform(target)
print(f"Input needed: {answer}")

# Verify
transformed = ""
for c in answer:
    new_char = ord(c) + 13
    if new_char > ord('z'):
        new_char -= 26
    transformed += chr(new_char)
print(f"After transformation: {transformed}")
print(f"Matches target: {transformed == target}")

# flag{babyreversing}
