from pwn import *

p = remote('recruit.osiris.bar', 50003)

print(p.recvuntil(b"?: \n").decode())
msg = '60pherz are qtezt'
p.sendline(msg.encode())

p.interactive()

# flag{1zn't_G0_5u9er_w3iRd}
