from pwn import *
import string

# Connect to the server
def connect():
    return remote('recruit.osiris.bar', 41001)

def encrypt_text(r, text):
    r.send(b'0')  # Option 0
    r.recvuntil(b'encrypted\n')
    r.send('{:04d}'.format(len(text)).encode())
    r.send(text.encode())
    size = int(r.recv(4))
    return r.recv(size)

def get_flag_with_padding(r, padding):
    r.send(b'1')  # Option 1
    r.recvuntil(b'Flag\n')
    r.send('{:04d}'.format(len(padding)).encode())
    r.send(padding.encode())
    size = int(r.recv(4))
    return r.recv(size)

def find_block_size():
    r = connect()
    base_len = len(get_flag_with_padding(r, ''))
    pad = ''
    while len(get_flag_with_padding(r, pad)) == base_len:
        pad += 'A'
    r.close()
    return len(pad)

def leak_flag():
    block_size = 16  # AES block size is 16 bytes
    known = ''
    charset = string.printable
    
    while True:
        r = connect()
        current_block = len(known) // block_size
        pad_len = (block_size - (len(known) % block_size) - 1)
        padding = 'A' * pad_len
        
        # Get the encrypted flag with our padding
        target = get_flag_with_padding(r, padding)
        
        found = False
        for c in charset:
            test_input = padding + known + c
            encrypted = get_flag_with_padding(r, test_input)
            
            # Compare the blocks up to and including the current working block
            target_blocks = target[:(current_block + 1) * block_size]
            encrypted_blocks = encrypted[:(current_block + 1) * block_size]
            
            if encrypted_blocks == target_blocks:
                known += c
                found = True
                print("Found character:", c)
                print("Current flag:", known)
                break
        
        r.close()
        
        if not found:
            break
    
    return known

def main():
    print("Starting flag leak...")
    flag = leak_flag()
    print("Final flag:", flag)

if __name__ == '__main__':
    main() 

# flag{have_u_43aRd_0f_tHe_3CB_penGuIn}
