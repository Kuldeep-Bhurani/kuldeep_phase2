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

