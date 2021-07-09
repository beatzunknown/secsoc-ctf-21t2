#!/usr/bin/python3

# SKYLIGHT{cR4cK3d_My_0bfu$c4TeD_5tr!nGs}

from pwn import *

PROG_NAME = "./misrocoft-orifice"
REMOTE_IP = "pwn.ctf.unswsecurity.com"
REMOTE_PORT = 5004

if args.REMOTE:
    p = remote(REMOTE_IP, REMOTE_PORT)
    elf = ELF(PROG_NAME)
else:
    p = process(PROG_NAME)
    elf = p.elf

if args.ATTACH:
	gdb.attach(p, '''break main''')

"""
XXXXX-XXXXX-XXXXX-XXXXX-XXXXX

L34KS at pos 6
XXXXX-L34KS-XXXXX-XXXXX-XXXXX

BDQC3 in seg0
BDQC3-L34KS-XXXXX-XXXXX-XXXXX

hex \x16\x10s\xb3% XOR %S!\x83q
BDQC3-L34KS-3CR0T-XXXXX-XXXXX

cseg3_4(&var_26, 0x134, 0x2d4)
sum of chars = 0x134 = 308

sum of code[4-i]*i = 0x2d4 = 724
0x30*4 = 192
532


a + b + c + d + e = 308
4*a + 3*b + 2*c + 1*d = 724
simultaneous equation solver


"""

poss = [i for i in range(ord('0'), ord('9')+1)]
poss += [i for i in range(ord('A'), ord('Z')+1)]

def brute(x, y):
    for a in poss:
        for b in poss:
            for c in poss:
                for d in poss:
                    for e in poss:
                        if (a + b + c + d + e == x):
                            if (4*a + 3*b + 2*c + 1*d == y):
                                vals = [a, b, c, d, e]
                                return ''.join(map(chr, vals))

payload = f'3CQDB-LE4K5-3CR0T-{brute(0x134, 0x2d4)}-{brute(0x13b, 0x2b2)}'

p.sendline(payload)

p.interactive()

