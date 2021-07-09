#!/usr/bin/python3

# A simple binary enumeration script

import sys
from pwn import *

if len(sys.argv) < 2:
	exit()

PROG_NAME = sys.argv[1]

p = process(PROG_NAME)
elf = p.elf

elf.checksec()
HAS_WIN = 'win' in elf.symbols
print("Has win:", HAS_WIN)
HAS_SYSTEM = 'system' in elf.plt
print("Has system:", HAS_SYSTEM)
HAS_EXECVE = 'execve' in elf.plt
print("Has execve:", HAS_EXECVE)

p.interactive()
p.sendline(cyclic(0x1000))
p.wait()
core = Coredump('./core')
print("bof offset:", cyclic_find(core.eip))

