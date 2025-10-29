import re

data = open("firmware.elf", "rb").read()
p = re.compile(rb"[A-Za-z0-9_]{1,20}\{[A-Za-z0-9_\-\+\=\/\\\.\s]{10,200}\}")

for k in range(1, 256):
    decoded = bytes(b ^ k for b in data)
    match = p.search(decoded)
    if match:
        print("Key:", k, "Flag:", match.group().decode())


