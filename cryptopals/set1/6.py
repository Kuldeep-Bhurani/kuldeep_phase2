# hamming distance fn
def hamming(b1, b2):
    distance = 0
    if(len(b1) != len(b2)):
        return -1
    for a,b in zip(b1,b2):
        distance += (bin(a^b).count('1'))
    return distance

def single_bit_XOR_decode(byte_str, k):
    # byte_str = bytes.fromhex(hex_str)
    return bytes([b ^ k for b in byte_str])

# single_bit_XOR_decode(encoded, i).decode('utf-8') where i ranges in (0 .. 255)

# data input
with open("6.txt", 'rb') as file:
        enc_data = file.read()
# enc_data = bytes(enc_data)
keyszs = []
dists = []
for keysz in range(1, 41):
    dist = hamming(enc_data[:keysz], enc_data[keysz:2*keysz])
    dist = dist // keysz
    # print(f"keysz, dist = [{keysz}, {dist}]")
    keyszs.append(keysz)
    dists.append(dist)
kd = dict(zip(keyszs, dists))
kd = sorted(kd.items(), key=lambda item: item[1])
kd = kd[:4]
print(kd)

for i in kd:
    keysz = i[0]
    chunked_enc = []
    if(len(enc_data)%keysz == 0):
        for j in range(0, len(enc_data), keysz):
            chunked_enc.append(enc_data[j:j+keysz])
    for k in range(keysz):
        vert_chunk_enc = bytes([c[k] for c in chunked_enc])
        vert_chunk_decs = []
        for r in range(255):
            try:
                vert_chunk_dec = single_bit_XOR_decode(vert_chunk_enc, r).decode('ascii')
                vert_chunk_decs.append(vert_chunk_dec)
            except:
                print("skip")
        print(vert_chunk_decs)
# test
# s1 = b"this is a test"
# s2 = b"wokka wokka!!!"
# print(hamming(s1, s2))

