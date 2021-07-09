#!/usr/bin/python3

# SKYLIGHT{hop3_y0u_Lik3_m0duLus}

from pwn import *

PROG_NAME = "./vuln"
REMOTE_IP = "pwn.ctf.unswsecurity.com"
REMOTE_PORT = 5005

if args.REMOTE:
    p = remote(REMOTE_IP, REMOTE_PORT)
    elf = ELF(PROG_NAME)
else:
    p = process(PROG_NAME)
    elf = p.elf

if args.ATTACH:
	gdb.attach(p, '''break main''')

"""
eax_2 = strlen(b) == 14
i = 0
j = 5
while (i <= 13)
    if original[i] == payload[j%eax_2]
"""
original = "skylight_cyb3r"
payload = ""

j = 5;
for i, c in enumerate(original):
    payload += original[j % len(original)]
    j += 5

p.sendline(payload)

p.interactive()