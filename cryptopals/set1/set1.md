# Cryptopals Crypto Challenge Set 1

## 1. Convert hex to base64

We have to write a code to convert hex to base64

Given Input:
> 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d

Should Produce:
> SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t

### My Solution

**Steps:**

- Wrote a simple python script and ran it

> _1.py_
```python
from pwn import *

# b64e() fn and unhex() fn required

hex_str = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'

raw_bytes = unhex(hex_str)

b64_str = b64e(raw_bytes)

print(f"hex_str: {hex_str}\nraw_bytes: {raw_bytes}\nb64_str: {b64_str}")
```

```bash
$ python3 1.py
hex_str: 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
raw_bytes: b"I'm killing your brain like a poisonous mushroom"
b64_str: SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
```

- Other methods to solve this could be by the use of `base64` library in python or by the combination of `base64` command and python console 

## 2. Convert hex to base64

We have to write a code to find XOR of 2 hex str

Given Inputs:
> 1c0111001f010100061a024b53535009181c
> 686974207468652062756c6c277320657965

Should Produce:
> 746865206b696420646f6e277420706c6179

### My Solution

**Steps:**

- Wrote a simple python script and ran it

> _2.py_
```python
hex_str1 = '1c0111001f010100061a024b53535009181c'
hex_str2 = '686974207468652062756c6c277320657965'

def XORfn(buf1, buf2):
    xor = 0
    if(len(buf1) == len(buf2)):
        xor = int(buf1, 16) ^ int(buf2, 16)
    return hex(xor)

print(XORfn(hex_str1, hex_str2)[2:])
```

```bash
$ python3 2.py
746865206b696420646f6e277420706c6179
```

## 3. Single-byte XOR cipher

We have a string XOR-ed with a single char we have to figure out the key and and decrypt the message

Given Inputs:
> 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736

### My Solution

**Flag:**`Cooking MC's like a pound of bacon`

**Steps:**

- Wrote a simple python script and ran it

> _3.py_
```python
encoded = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'

def XORfn(hex_str, k):
    byte_str = bytes.fromhex(hex_str)
    return bytes([b ^ k for b in byte_str])

# for c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ":
#    print(f"key: {[c, ord(c)]}\tunXOR-ed: {XORfn(encoded, ord(c)).decode('utf-8')}")
for i in range(255):
    try:
        print(f"key: {[chr(i), i]}\tunXOR-ed: {XORfn(encoded, i).decode('utf-8')}")
    except:
        print(f"Skipping {i}")

```

```bash
$ python3 3.py > out3py
```

- Finally I perused the file to get the string of text

[out3py](./out3py)

> _out3py_
```text
...
key: ['X', 88]	unXOR-ed: Cooking MC's like a pound of bacon
...
```

## 4. Detect single-character XOR

Out of 60 given hex strings in the given `4.txt` file we have one that has been encoded via xor-ring we have to find the string and decode it

[4.txt](./4.txt)

### My Solution

**Flag:**`Now that the party is jumping`

**Steps:**

- Wrote a simple python script and ran it

> _4.py_
```python
def XORfn(hex_str, k):
    byte_str = bytes.fromhex(hex_str)
    return bytes([b ^ k for b in byte_str])

with open("4.txt", 'r') as file:
        lines = file.readlines()
        for line in lines:
            encoded = line.strip()
            print(f"----- ENCODED = {encoded} ------")
            for i in range(255):
                try:
                    print(f"key: {[chr(i), i]}\tunXOR-ed: {XORfn(encoded, i).decode('utf-8')}")
                except:
                    pass
```

```bash
$ python3 4.py > out4py
```

- Finally I perused the file to get the string of text

[out4py](./out4py)

> _out4py_
```text
...
----- ENCODED = 7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f ------
...

key: ['5', 53]	unXOR-ed: Now that the party is jumping
...
```

## 5. Implement repeating-key XOR

We have to implement repeating-key XOR and encrypt the given text with the given key

Given Text:
> Burning 'em, if you ain't quick and nimble 
> I go crazy when I hear a cymbal

Given Key:
> ICE 

Expected Output:
> 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
> a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f

### My Solution

**Steps:**

- Wrote a simple python script and ran it

> _5.py_
```python
plaintxt = b'Burning \'em, if you ain\'t quick and nimble\nI go crazy when I hear a cymbal'

key = "ICE"

ciphertxt = bytearray(len(plaintxt))
for (i, b) in enumerate(plaintxt):
    ciphertxt[i] = (b ^ ord(key[i%len(key)]))

ciphertxt = bytes(ciphertxt)

print(ciphertxt)
print(ciphertxt.hex())
```

```bash
$ python3 5.py
b'\x0b67\'*+.cb,.ii*#i:*<c$ -b=c4<*&"c$\'\'e\'*(+/ C\ne.,e*1$3:e>+ \'c\x0ci+ (1e(c&0.\'(/'
0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
```

- Which matches the expected output and hence we can move forward

## 6. Break repeating-key XOR

We have to decrypt the data of a file which has been base64'd and then encrypted with repeating-key XOR

Given File:
- [6.txt](https://cryptopals.com/static/challenge-data/6.txt)

### My Solution

**Steps:**

- Wrote a simple python script and ran it

> _6.py_
```python
```

```bash
```


