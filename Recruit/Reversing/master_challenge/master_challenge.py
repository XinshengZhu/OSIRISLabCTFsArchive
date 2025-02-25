from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-f']

# p = gdb.debug(CHALLENGE, '''
#     b *(stage_3+114872)
#     continue
# ''')

CHALLENGE = './main'
URL = 'recruit.osiris.bar'
PORT = 50004
LOCAL = False

def brute_force():
    for i in range(1024):
        for j in range(1024):
            p = process(CHALLENGE)
            p.recvuntil(b"!!!!!\n")
            p.sendline("sooo_whats_that_blinky_red_light?".encode())
            p.recvuntil(b"!!\n")
            p.sendline(str(7).encode())
            p.sendline(str(7).encode())
            p.recvuntil(b"!!\n")
            p.sendline(str(i).encode())
            p.sendline(str(j).encode())
            if b"[boom]" in p.recvline():
                print(f"Boom at {i} {j}")
                p.close()
            else:
                print(f"Success at {i} {j}")
                exit(0)

if LOCAL:
    p = process(CHALLENGE)
    brute_force()
else:
    p = remote(URL, PORT)
    p.recvuntil(b"!!!!!\n")
    p.sendline("sooo_whats_that_blinky_red_light?".encode())
    p.recvuntil(b"!!\n")
    p.sendline(str(7).encode())
    p.sendline(str(7).encode())
    p.recvuntil(b"!!\n")
    p.sendline(str(158).encode())
    p.sendline(str(620).encode())
    p.interactive()

# flag{W3lcom3_2_the_l4b_reeeecruit<3}
