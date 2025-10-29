from pwn import *

connection = remote('titan.picoctf.net', 64389)

connection.recvuntil('decrypt.')
payload = b'E\n'
connection.send(payload)
connection.recvuntil('keysize):')
payload = b'\x02\n'
connection.send(payload)
connection.recvuntil('ciphertext (m ^ e mod n)')

response = connection.recvline()
num = int(response.decode())
num = num*2575135950983117315234568522857995277662113128076071837763492069763989760018604733813265929772245292223046288098298720343542517375538185662305577375746934

connection.recvuntil('decrypt.')
payload = b'D' + b'\n'
connection.send(payload)
connection.recvuntil('decrypt:')
connection.send(str(num)+'\n')

connection.recvuntil('hex (c ^ d mod n):')
response = connection.recvline()
print(response.decode())

num=int(response,16)//2
print(hex(num))

hex_string = hex(num)[2:]
byte_array = bytes.fromhex(hex_string)
print(byte_array.decode('ascii'))

connection.close()

