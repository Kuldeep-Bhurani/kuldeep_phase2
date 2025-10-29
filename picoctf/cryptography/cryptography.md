# Cryptography

## 1. rsa_oracle

The challenge is to decrypt `password` and use the `password` to decrypt the message `secret` 

We have an `oracle` which is from where the password has been encoded but it will decode anything other than password

Challenge Files:
- [secret.enc](./rsa-oracle/secret.enc)
- [password.enc](./rsa-oracle/password.enc)

Challenge Endpoint:
- oracle: nc titan.picoctf.net [PORT] (PORT is generated automatically when the challenge is launched)

### My Solution

**Flag:**`picoCTF{su((3ss_(r@ck1ng_r3@_24bcbc66}`

**Steps:**

- As we have the oracle, I first tried to figure out what it does

```bash
$ nc titan.picoctf.net [PORT]
*****************************************
****************THE ORACLE***************
*****************************************
what should we do for you?
E --> encrypt D --> decrypt.
E
enter text to encrypt (encoded length must be less than keysize): 1
1

encoded cleartext as Hex m: 31

ciphertext (m ^ e mod n) 4374671741411819653095065203638363839705760144524191633605358134684143978321095859047126585649272872908765432040943055399247499744070371810470682366100689

what should we do for you?
E --> encrypt D --> decrypt.
D
Enter text to decrypt: 4374671741411819653095065203638363839705760144524191633605358134684143978321095859047126585649272872908765432040943055399247499744070371810470682366100689
decrypted ciphertext as hex (c ^ d mod n): 31
decrypted ciphertext: 1
```

- So basically the `oracle` is using RSA encryption where to encode it uses `c = m ^ e mod n` and to decode it uses `m = c ^ d mod n`

- 2 of My Solution didn't go as planned: [Failed Solutions](#failed-solutions)

- So, I tried it another way which was to exploit the basic mathematics of the system as follows:
    - We know that `m ^ e mod n = c1` and `k ^ e mod n = c2` so `c1*c2` becomes `(m*k) ^ e mod n`
    - now if one of these cyphertext is our password and for other both the value of cyphertext and plaintext is know to us then we can use the oracle to decode `c1*c2`
    - say our cyphertext is `c1` and `k` is `2` then we encode 2 and then multiply the cyphertext and then decode the final value

- Next step was to impliment this using a python script

> _soln.py_
```python
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
```

```bash
$ python3 soln.py
[+] Opening connection to titan.picoctf.net on port 64389: Done
 6468c4c6c4

0x3234626362
24bcb
```

- After running this script we get out password which is `24bcb`

- Now, I wasn't able to progress further without taking a hint so I did and I found out that I have to use `openssl` to decrypt the message 

- Finally I ran `openssl` with the asymmetric 256 bit cipher block chaining encoding and decrypted the file `secret.enc` using the key `24bcb` to get the flag

```bash
$ openssl enc -aes-256-cbc -d -in secret.enc -k 24bcb
*** WARNING : deprecated key derivation used.
Using -iter or -pbkdf2 would be better.
picoCTF{su((3ss_(r@ck1ng_r3@_24bcbc66}
```

### Failed Solutions

- To decode the password we need to find out the value of the private key `d`

- For the input I have entered above, `c` is `0x5386f33679120a440b9dabace3dcfd599bcabc06f1d1f0d1c5f395d86311e42c58dd2ffebc1291cc22ecfec6a06615436282779b7c609377c3c9121ef8f8c4d1` or `4374671741411819653095065203638363839705760144524191633605358134684143978321095859047126585649272872908765432040943055399247499744070371810470682366100689`, `m` is `0x31` and assuming `e` is `0x10001` or `25537` we can figure out the value of `n`

- k<sub>1</sub>n = m ^ e - c (where k<sub>1</sub> is some integer)

- Now if I do the same for another input value say `2`, i can get a different value for k

- k<sub>2</sub>n = m ^ e - c

- And we can just find out the value of n by calculating the gcd of these 2 k<sub>i</sub>*n

- Now, I wasn't able to proceed through this method so, I though of using brute-force to find `n` basically if `n` is small enough we can brute it due to the `mod n` in our expression so, when our output is of length 1 we find that n is a multiple of 1 smaller than that length 

- But this method also failed

## 2. Custom encryption

The challenge is to decrypt `enc_flag` by getting a sense of the code in `custom_encryption.py` and writing a function

Challenge Files:
- [enc_flag](./customenc/enc_flag)
- [custom_encryption.py (updated)](./customenc/custom_encryption.py)

### My Solution

**Flag:**`picoCTF{custom_d2cr0pt6d_dc499538}`

**Steps:**

- First I looked at the `enc_flag` file and ran the `custom_encryption.py` file to get a sense of the output

- Then I started with analysing the `custom_encryption.py` file and writing the function `decode` to decode it with which I also added the `dynamic_xor_decrypt` helper function

- I had edited the `custom_encryption.py` file itself and I have added `comments` indicating which code is `MY ADDITION` and I am also adding that code here 

- After testing of the code, I added the given `cipher` and values of `a` and `b` and assumed that the `text_key` remains the same as during test

> _custom_encryption.py_
```python
# ---------MYADDITION-----------
def dynamic_xor_decrypt(cipher, text_key):
    plaintxt = ""
    key_length = len(text_key)
    for i, char in enumerate(cipher):
        key_char = text_key[i % key_length]
        decrypted_char = chr(ord(char) ^ ord(key_char))
        plaintxt += decrypted_char
    return plaintxt[::-1]


# ---------MYADDITION-----------
def decode(cipher, a, b, text_key):
    # for the question the value of a, b is given from which we can find out the value of g and p as we know g and p will be numbers greater than a and b by a maximum of 10 and prime
    ps = [] # possible vals of p
    gs = [] # possible vals of g
    for i in range(a, a+11):
        if(is_prime(i)):
            ps.append(i)
    for i in range(b, b+11):
        if(is_prime(i)):
            gs.append(i)
    print(ps, gs);
    for p in ps:
        for g in gs:
            # for each combination of p and g we decode the cipher
            u = generator(g, a, p) # g^a % p
            v = generator(g, b, p) # g^b % p
            key = generator(v, a, p) # v^a % p
            b_key = generator(u, b, p) # u^b % p
            shared_key = None
            if key == b_key:
                shared_key = key
            else:
                print("Invalid key")
                return
            print(f'shared key is: {shared_key}')
            # decryption
            semi_cipher = ""
            for c in cipher:
                charcode = c // shared_key;
                charcode = charcode // 311;
                semi_cipher = semi_cipher + chr(int(charcode))
            # de-xor
            plaintxt = dynamic_xor_decrypt(semi_cipher, text_key); # both encryption and decryption remains same for XOR
            print(plaintxt)

if __name__ == "__main__":
    # message = sys.argv[1]
    # cipher = test(message, "trudeau") # trudeau is the text key
    # ---------MYADDITION-----------
    # ab = eval(input("list [a, b]: "))
    # -- chall input
    cipher = [33588, 276168, 261240, 302292, 343344, 328416, 242580, 85836, 82104, 156744, 0, 309756, 78372, 18660, 253776, 0, 82104, 320952, 3732, 231384, 89568, 100764, 22392, 22392, 63444, 22392, 97032, 190332, 119424, 182868, 97032, 26124, 44784, 63444]
    ab = [89, 27]
    decode(cipher, ab[0], ab[1], "trudeau") 
```

- Finally, I ran the python script to get the flag

```bash
$ python3 custom_encryption.py
[89, 97] [29, 31, 37]
shared key is: 14
oobcXo^w`jpwcaTe-grNqs"dQ`gB*+!IMs
shared key is: 86
cddvtprbefurwviehvr}ucndpqw|mio|xu
shared key is: 12
picoCTF{custom_d2cr0pt6d_dc499538}
shared key is: 42
effr|}{fd`tssspe|srgtgrdytrgxsagv
shared key is: 12
picoCTF{custom_d2cr0pt6d_dc499538}
shared key is: 19
kb`el`UqfnvqezFeRxr^vlQdoz\V_WY\q
```

## 3. Mini RSA

In this challenge we have to decrypt the given ciphertext

Challenge Description:
> What happens if you have a small exponent? There is a twist though, we padded the plaintext so that (M ** e) is just barely larger than N

Challenge Files:
- [ciphertext](./miniRSA/ciphertext)

### My Solution

**Flag:**``

**Steps:**

- 
