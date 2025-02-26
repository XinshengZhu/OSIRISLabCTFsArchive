from pwn import *

def is_palindrome(s):
    return s == s[::-1]

def generate_palindrome():
    start = "aqua"
    middle = "hackthis"
    palindrome = start + middle + middle[::-1] + start[::-1]
    return palindrome

solution = generate_palindrome()
assert len(solution) > 0x13, "Length must be > 19"
assert solution.startswith("aqua"), "Must start with 'aqua'"
assert is_palindrome(solution), "Must be a palindrome"
print(f"Solution found: {solution}")
print(f"Length: {len(solution)}")

p = remote('recruit.osiris.bar', 50000)

p.sendline(solution.encode())

p.interactive()

# flag{4actu4l_r3v3rs1ng_st4rts_n0w}
