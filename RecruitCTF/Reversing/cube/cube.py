from pwn import *

p = remote('recruit.osiris.bar', 50001)

print(p.recvuntil(b"Enter your moves: (One at a time: Use # to finish early)\n").decode())
moves = ["D", "L'", "F'", "D'", "B'", "R", "R", "F'", "R'", "F", "F", "U'", "F", "B", "B", "U", "U", "R", "R", "D'", "B", "B", "U", "U", "R", "R", "U", "U", "L", "L", "#"]
for move in moves:
    p.sendline(move.encode())
    sleep(1)

p.interactive()

# flag{ea00610ef917558d1cffe6ce257279dcc8641b3d}
# https://rubiks-cube-solver.com/zh/solution.php?cube=0231646322626136224451363541554454422515615146653321313
