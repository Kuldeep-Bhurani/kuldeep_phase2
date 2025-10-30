hex_str1 = '1c0111001f010100061a024b53535009181c'
hex_str2 = '686974207468652062756c6c277320657965'

def XORfn(buf1, buf2):
    xor = 0
    if(len(buf1) == len(buf2)):
        xor = int(buf1, 16) ^ int(buf2, 16)
    return hex(xor)

print(XORfn(hex_str1, hex_str2)[2:])
