plaintxt = b'Burning \'em, if you ain\'t quick and nimble\nI go crazy when I hear a cymbal'

key = "ICE"

ciphertxt = bytearray(len(plaintxt))
for (i, b) in enumerate(plaintxt):
    ciphertxt[i] = (b ^ ord(key[i%len(key)]))

ciphertxt = bytes(ciphertxt)

print(ciphertxt)
print(ciphertxt.hex())
