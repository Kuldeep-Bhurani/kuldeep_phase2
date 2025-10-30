# hamming distance fn
def hamming(b1, b2):
    distance = 0
    if(len(b1) != len(b2)):
        return -1
    for a,b in zip(b1,b2):
        distance += (bin(a^b).count('1'))
    return distance

# data input
enc_data = ""
with open("6.txt", 'r') as file:
        lines = file.readlines()
        for line in lines:
            line = line.strip() 
        enc_data = ''.join(lines)

# test
# s1 = b"this is a test"
# s2 = b"wokka wokka!!!"
# print(hamming(s1, s2))

